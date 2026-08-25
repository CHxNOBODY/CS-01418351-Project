"""The KUFT/2.0 server: TLS 1.3, pairing-code auth, a jailed share directory.

One thread per connection, bounded by a semaphore.  A session is a small state
machine -- greeted, then authenticated, then able to move files -- and every
handler runs inside the root jail, so no request can name a path outside the
shared directory.
"""

from __future__ import annotations

import argparse
import hmac
import os
import socket
import ssl
import sys
import tempfile
import threading
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

from . import term
from .crypto import (
    ServerIdentity,
    b64,
    client_proof,
    new_nonce,
    server_proof,
    unb64,
)
from .protocol import (
    CHUNK,
    Reader,
    Request,
    Response,
    Writer,
    ProtocolError,
    body_length,
    checksum_file,
    error_response,
    join_lines,
)

DEFAULT_PORT = 5150
DEFAULT_MAX_CLIENTS = 8
RATE_WINDOW = 10.0


class Jail:
    """Resolves request targets to real paths, refusing anything outside root.

    Traversal is checked after ``resolve()``, which collapses ``..`` and
    follows symlinks -- so a symlink pointing out of the share is rejected too,
    not just a literal ``../`` in the target.
    """

    def __init__(self, root: Path):
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def resolve(self, target: str) -> Path:
        cleaned = (target or "/").replace("\\", "/").strip()
        if cleaned in ("", "/", "."):
            return self.root
        if "\x00" in cleaned:
            raise ProtocolError("NUL in path", 400)
        candidate = (self.root / cleaned.lstrip("/")).resolve()
        if candidate != self.root and self.root not in candidate.parents:
            raise ProtocolError("path escapes the shared directory", 403)
        return candidate

    def display(self, path: Path) -> str:
        try:
            rel = path.relative_to(self.root).as_posix()
        except ValueError:
            return path.name
        return rel or "/"


class RateLimiter:
    """Fixed-window request counter, per connection."""

    def __init__(self, limit: int):
        self.limit = limit
        self.events: deque[float] = deque()

    def allow(self) -> bool:
        if self.limit <= 0:
            return True
        now = time.monotonic()
        while self.events and now - self.events[0] > RATE_WINDOW:
            self.events.popleft()
        if len(self.events) >= self.limit:
            return False
        self.events.append(now)
        return True


class Config:
    def __init__(self, args: argparse.Namespace, identity: ServerIdentity):
        self.host: str = args.host
        self.port: int = args.port
        self.jail = Jail(Path(args.share))
        self.read_only: bool = args.read_only
        self.max_clients: int = args.max_clients
        self.rate_limit: int = args.rate_limit
        self.max_upload: int = args.max_upload * 1024 * 1024
        self.identity = identity
        self.verbose: bool = args.verbose


class Session:
    """One client connection, from TLS handshake to QUIT."""

    def __init__(self, conn: ssl.SSLSocket, peer: tuple, cfg: Config):
        self.conn = conn
        self.peer = f"{peer[0]}:{peer[1]}"
        self.cfg = cfg
        self.authenticated = False
        self.greeted = False
        self.limiter = RateLimiter(cfg.rate_limit)
        self.s_nonce = new_nonce()
        self.stream = conn.makefile("rwb")
        self.reader = Reader(self.stream)
        self.writer = Writer(self.stream)

    # ------------------------------------------------------------- plumbing

    def log(self, text: str, *styles: str) -> None:
        print(f"{term.paint(term.stamp(), 'grey')} {term.paint(self.peer, 'blue')} {term.paint(text, *styles)}")

    def log_status(self, method: str, target: str, resp: Response) -> None:
        colour = "green" if resp.ok else ("yellow" if resp.code < 500 else "red")
        self.log(
            f"{method} {target[:48]} -> {resp.code} {resp.phrase}"
            + (f" ({resp.headers.get('detail', '')})" if self.cfg.verbose else ""),
            colour,
        )

    def reply(self, resp: Response, body: bytes = b"") -> None:
        self.writer.send_bytes(resp, body)

    # ---------------------------------------------------------------- loop

    def run(self) -> None:
        cipher = self.conn.cipher()
        self.log(
            f"connected  {self.conn.version()} {cipher[0] if cipher else '?'}", "cyan"
        )
        try:
            while True:
                try:
                    request = self.reader.read_request()
                except ProtocolError as exc:
                    # Framing is broken; we cannot trust the stream any more.
                    self.reply(error_response(exc.code, exc.detail, connection="close"))
                    self.log(f"protocol error -> {exc.code} {exc.detail}", "red")
                    return

                if not self.limiter.allow():
                    resp = error_response(
                        429,
                        f"more than {self.cfg.rate_limit} requests in {RATE_WINDOW:.0f}s",
                        **{"retry-after": "10"},
                    )
                    self._discard_body(request)
                    self.reply(resp)
                    self.log_status(request.method, request.target, resp)
                    continue

                if request.method == "QUIT":
                    resp = Response(200, {"detail": "goodbye", "connection": "close"})
                    self.reply(resp)
                    self.log_status("QUIT", request.target, resp)
                    return

                try:
                    self.dispatch(request)
                except ProtocolError as exc:
                    resp = error_response(exc.code, exc.detail)
                    self.reply(resp)
                    self.log_status(request.method, request.target, resp)
                except (BrokenPipeError, ConnectionResetError):
                    raise
                except OSError as exc:
                    resp = error_response(500, f"server error: {exc.strerror or exc}")
                    self.reply(resp)
                    self.log_status(request.method, request.target, resp)
        except (ConnectionError, ssl.SSLError, TimeoutError) as exc:
            self.log(f"connection lost: {exc.__class__.__name__}", "yellow")
        finally:
            try:
                self.stream.close()
            except OSError:
                pass
            self.log("disconnected", "grey")

    def _discard_body(self, request: Request) -> None:
        """Consume and throw away a body we are refusing, to keep sync."""
        remaining = body_length(request.headers)
        while remaining > 0:
            block = self.reader.stream.read(min(CHUNK, remaining))
            if not block:
                break
            remaining -= len(block)

    def dispatch(self, request: Request) -> None:
        handlers = {
            "HELLO": self.do_hello,
            "AUTH": self.do_auth,
            "LIST": self.do_list,
            "STAT": self.do_stat,
            "GET": self.do_get,
            "PUT": self.do_put,
            "DELETE": self.do_delete,
            "MKDIR": self.do_mkdir,
            "MOVE": self.do_move,
        }
        handler = handlers.get(request.method)
        if handler is None:
            raise ProtocolError(f"{request.method} is not implemented", 405)

        if request.method not in ("HELLO", "AUTH") and not self.authenticated:
            self._discard_body(request)
            raise ProtocolError("pair first -- this session is not authenticated", 401)

        if self.cfg.read_only and request.method in ("PUT", "DELETE", "MKDIR", "MOVE"):
            self._discard_body(request)
            raise ProtocolError("this server is running read-only", 403)

        handler(request)

    # ------------------------------------------------------------ handlers

    def do_hello(self, request: Request) -> None:
        self.greeted = True
        resp = Response(
            200,
            {
                "server": f"kuft-server/2.0 ({sys.platform})",
                "methods": ",".join(
                    ["HELLO", "AUTH", "LIST", "STAT", "GET", "PUT", "DELETE", "MKDIR", "MOVE", "QUIT"]
                ),
                "tls": self.conn.version() or "unknown",
                "auth": "pairing-code",
                "salt": b64(self.cfg.identity.salt),
                "nonce": b64(self.s_nonce),
                "read-only": "true" if self.cfg.read_only else "false",
                "max-upload": str(self.cfg.max_upload),
                "detail": "send AUTH with your pairing proof",
            },
        )
        self.reply(resp)
        self.log_status("HELLO", request.target, resp)

    def do_auth(self, request: Request) -> None:
        """Verify the client's channel-bound proof, then prove ourselves back."""
        if not self.greeted:
            raise ProtocolError("send HELLO before AUTH", 400)
        try:
            c_nonce = unb64(request.headers.get("nonce", ""))
            proof = unb64(request.headers.get("proof", ""))
        except ValueError:
            raise ProtocolError("nonce and proof must be base64", 400) from None
        if len(c_nonce) < 16 or len(proof) != 32:
            raise ProtocolError("malformed nonce or proof", 400)

        fingerprint = self.cfg.identity.fingerprint
        expected = client_proof(self.cfg.identity.auth_key, fingerprint, c_nonce, self.s_nonce)

        if not hmac.compare_digest(expected, proof):
            # Slow a guessing client down without blocking the whole server.
            time.sleep(1.0)
            resp = error_response(401, "pairing code does not match")
            self.reply(resp)
            self.log_status("AUTH", request.target, resp)
            return

        self.authenticated = True
        resp = Response(
            200,
            {
                "proof": b64(
                    server_proof(self.cfg.identity.auth_key, fingerprint, c_nonce, self.s_nonce)
                ),
                "share": self.cfg.jail.root.name,
                "detail": "paired -- session authenticated",
            },
        )
        self.reply(resp)
        self.log_status("AUTH", request.target, resp)

    def do_list(self, request: Request) -> None:
        path = self.cfg.jail.resolve(request.target)
        if not path.exists():
            raise ProtocolError(f"no such directory: {request.target}", 404)
        if not path.is_dir():
            raise ProtocolError(f"not a directory: {request.target}", 400)

        rows = []
        for entry in sorted(path.iterdir(), key=lambda p: (p.is_file(), p.name.lower())):
            try:
                info = entry.stat()
            except OSError:
                continue
            kind = "DIR" if entry.is_dir() else "FILE"
            size = "-" if entry.is_dir() else str(info.st_size)
            modified = datetime.fromtimestamp(info.st_mtime, timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
            rows.append(f"{kind}\t{size}\t{modified}\t{entry.name}")

        body = join_lines(rows) if rows else b""
        resp = Response(
            200,
            {
                "content-type": "text/tab-separated-values; charset=utf-8",
                "count": str(len(rows)),
                "path": self.cfg.jail.display(path),
                "detail": f"{len(rows)} " + ("entry" if len(rows) == 1 else "entries"),
            },
        )
        self.reply(resp, body)
        self.log_status("LIST", request.target, resp)

    def do_stat(self, request: Request) -> None:
        path = self.cfg.jail.resolve(request.target)
        if not path.exists():
            raise ProtocolError(f"no such file: {request.target}", 404)
        info = path.stat()
        headers = {
            "kind": "dir" if path.is_dir() else "file",
            "size": str(info.st_size),
            "modified": datetime.fromtimestamp(info.st_mtime, timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            "detail": f"metadata for {self.cfg.jail.display(path)}",
        }
        if path.is_file():
            headers["checksum"] = checksum_file(path)
        resp = Response(200, headers)
        self.reply(resp)
        self.log_status("STAT", request.target, resp)

    def do_get(self, request: Request) -> None:
        path = self.cfg.jail.resolve(request.target)
        if not path.exists() or path.is_dir():
            raise ProtocolError(f"no such file: {request.target}", 404)

        size = path.stat().st_size
        offset = 0
        raw_range = request.headers.get("range")
        if raw_range:
            try:
                offset = int(raw_range)
            except ValueError:
                raise ProtocolError(f"range is not a number: {raw_range!r}", 400) from None
            if offset < 0 or offset > size:
                raise ProtocolError(f"range {offset} outside 0..{size}", 416)

        length = size - offset
        headers = {
            "content-type": "application/octet-stream",
            "size": str(size),
            "offset": str(offset),
            "checksum": checksum_file(path, offset=offset),
            "whole-checksum": checksum_file(path),
            "detail": f"sending {self.cfg.jail.display(path)}",
        }
        resp = Response(206 if offset else 200, headers)
        with open(path, "rb") as handle:
            if offset:
                handle.seek(offset)
            self.writer.send_stream(resp, handle, length)
        self.log_status("GET", request.target, resp)

    def do_put(self, request: Request) -> None:
        path = self.cfg.jail.resolve(request.target)
        length = body_length(request.headers)
        overwrite = request.headers.get("overwrite", "").lower() == "true"
        append_at = request.headers.get("range")

        if length > self.cfg.max_upload:
            self._discard_body(request)
            raise ProtocolError(
                f"upload is {length} octets, limit is {self.cfg.max_upload}", 413
            )
        if path.is_dir():
            self._discard_body(request)
            raise ProtocolError(f"{request.target} is a directory", 409)
        if path.exists() and not overwrite and not append_at:
            self._discard_body(request)
            raise ProtocolError(
                f"{request.target} already exists -- resend with overwrite", 409
            )
        path.parent.mkdir(parents=True, exist_ok=True)

        existed = path.exists()

        # Resumed upload: append into the partial file already on disk.
        if append_at:
            try:
                offset = int(append_at)
            except ValueError:
                self._discard_body(request)
                raise ProtocolError("range is not a number", 400) from None
            current = path.stat().st_size if path.exists() else 0
            if offset != current:
                self._discard_body(request)
                raise ProtocolError(
                    f"cannot resume at {offset}; server holds {current} octets", 416
                )
            with open(path, "r+b" if path.exists() else "wb") as handle:
                handle.seek(offset)
                self.reader.pipe_body(request.headers, handle)
            written = path.stat().st_size
            resp = Response(
                200,
                {
                    "size": str(written),
                    "checksum": checksum_file(path),
                    "detail": f"resumed to {written} octets",
                },
            )
            self.reply(resp)
            self.log_status("PUT", request.target, resp)
            return

        # Fresh upload: land it in a temp file, verify, then rename into place.
        # A failed transfer therefore never replaces a good file.
        fd, temp_name = tempfile.mkstemp(dir=str(path.parent), prefix=".kuft-", suffix=".part")
        temp_path = Path(temp_name)
        try:
            with os.fdopen(fd, "wb") as handle:
                written, digest = self.reader.pipe_body(request.headers, handle)

            claimed = request.headers.get("checksum")
            if claimed and claimed != digest:
                temp_path.unlink(missing_ok=True)
                raise ProtocolError(
                    f"checksum mismatch: expected {claimed[:23]}..., got {digest[:23]}...",
                    422,
                )
            os.replace(temp_path, path)
        except BaseException:
            temp_path.unlink(missing_ok=True)
            raise

        resp = Response(
            200 if existed else 201,
            {
                "size": str(written),
                "checksum": digest,
                "detail": ("replaced " if existed else "stored ")
                + self.cfg.jail.display(path),
            },
        )
        self.reply(resp)
        self.log_status("PUT", request.target, resp)

    def do_delete(self, request: Request) -> None:
        path = self.cfg.jail.resolve(request.target)
        if path == self.cfg.jail.root:
            raise ProtocolError("refusing to delete the share root", 403)
        if not path.exists():
            raise ProtocolError(f"no such file: {request.target}", 404)
        if path.is_dir():
            try:
                path.rmdir()
            except OSError:
                raise ProtocolError(f"directory is not empty: {request.target}", 409) from None
        else:
            path.unlink()
        resp = Response(204, {"detail": f"deleted {request.target}"})
        self.reply(resp)
        self.log_status("DELETE", request.target, resp)

    def do_mkdir(self, request: Request) -> None:
        path = self.cfg.jail.resolve(request.target)
        if path.exists():
            raise ProtocolError(f"{request.target} already exists", 409)
        path.mkdir(parents=True)
        resp = Response(201, {"detail": f"created {request.target}"})
        self.reply(resp)
        self.log_status("MKDIR", request.target, resp)

    def do_move(self, request: Request) -> None:
        destination = request.headers.get("destination")
        if not destination:
            raise ProtocolError("MOVE needs a destination header", 400)
        source = self.cfg.jail.resolve(request.target)
        target = self.cfg.jail.resolve(destination)
        if not source.exists():
            raise ProtocolError(f"no such file: {request.target}", 404)
        if target.exists():
            raise ProtocolError(f"{destination} already exists", 409)
        target.parent.mkdir(parents=True, exist_ok=True)
        os.replace(source, target)
        resp = Response(200, {"detail": f"{request.target} -> {destination}"})
        self.reply(resp)
        self.log_status("MOVE", request.target, resp)


# ----------------------------------------------------------------- listening


def build_ssl_context(identity: ServerIdentity) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(certfile=str(identity.cert_path), keyfile=str(identity.key_path))
    ctx.options |= ssl.OP_NO_COMPRESSION | ssl.OP_SINGLE_ECDH_USE
    return ctx


def lan_addresses() -> list[str]:
    """Addresses a client on the same network could actually reach us on."""
    found = []
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.settimeout(0.2)
        probe.connect(("10.255.255.255", 1))  # never sends a packet
        found.append(probe.getsockname()[0])
        probe.close()
    except OSError:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            addr = info[4][0]
            if addr not in found and not addr.startswith("127."):
                found.append(addr)
    except OSError:
        pass
    return found


def serve(cfg: Config) -> int:
    context = build_ssl_context(cfg.identity)
    slots = threading.Semaphore(cfg.max_clients)

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        listener.bind((cfg.host, cfg.port))
    except OSError as exc:
        term.fail(f"cannot bind {cfg.host}:{cfg.port} -- {exc.strerror or exc}")
        term.hint("another server may already be running; try --port 5151")
        return 1
    listener.listen(16)
    # Accept in slices rather than parking in one blocking call.  Windows does
    # not interrupt a blocking socket call for Ctrl+C: the console handler only
    # sets a flag, and that flag is turned into KeyboardInterrupt the next time
    # the interpreter runs bytecode.  Sitting in accept() forever means that
    # never happens, so the server ignores Ctrl+C until a client connects.
    listener.settimeout(0.5)

    reachable = lan_addresses() if cfg.host in ("0.0.0.0", "::") else [cfg.host]
    lines = [
        term.paint("KUFT/2.0 secure file share", "bold"),
        "",
        f"  sharing    {cfg.jail.root}"
        + (term.paint("  (read-only)", "yellow") if cfg.read_only else ""),
        f"  listening  {cfg.host}:{cfg.port}   TLS 1.3",
        "",
        term.paint("  On the other computer, run:", "bold"),
    ]
    for addr in reachable or [cfg.host]:
        lines.append(term.paint(f"    python kuft.py connect {addr} --port {cfg.port}", "cyan"))
    lines += [
        "",
        "  Pairing code   " + term.paint(cfg.identity.code, "green", "bold"),
        "  Fingerprint    " + term.paint(cfg.identity.pretty_fingerprint, "grey"),
    ]
    term.banner(lines)
    term.hint("the code is asked for once per client; Ctrl+C stops the server")
    print()

    try:
        while True:
            try:
                raw, peer = listener.accept()
            except socket.timeout:
                continue  # nobody knocked; loop so a pending Ctrl+C can land
            raw.settimeout(None)  # undo the listener's timeout on the new socket
            if not slots.acquire(blocking=False):
                _refuse(raw, context, cfg)
                continue

            def worker(raw=raw, peer=peer):
                try:
                    raw.settimeout(300)
                    conn = context.wrap_socket(raw, server_side=True)
                except (ssl.SSLError, OSError) as exc:
                    print(
                        f"{term.paint(term.stamp(), 'grey')} "
                        f"{term.paint(f'{peer[0]}:{peer[1]}', 'blue')} "
                        f"{term.paint(f'TLS handshake failed: {exc}', 'yellow')}"
                    )
                    raw.close()
                    slots.release()
                    return
                try:
                    Session(conn, peer, cfg).run()
                finally:
                    try:
                        conn.close()
                    except OSError:
                        pass
                    slots.release()

            threading.Thread(target=worker, daemon=True).start()
    except KeyboardInterrupt:
        print()
        term.info(term.paint("server stopped", "grey"))
        return 0
    finally:
        listener.close()


def _refuse(raw: socket.socket, context: ssl.SSLContext, cfg: Config) -> None:
    """Tell an over-capacity client 503 politely, inside TLS, then hang up."""
    try:
        conn = context.wrap_socket(raw, server_side=True)
        with conn.makefile("rwb") as stream:
            Writer(stream).send_bytes(
                error_response(
                    503,
                    f"server is full ({cfg.max_clients} sessions)",
                    connection="close",
                ),
                b"",
            )
        conn.close()
    except (ssl.SSLError, OSError):
        pass
    finally:
        try:
            raw.close()
        except OSError:
            pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="kuft.py serve", description="Share a directory over TLS 1.3."
    )
    parser.add_argument("--host", default="0.0.0.0", help="interface to bind (default: all)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--share", default="share", help="directory to share")
    parser.add_argument("--read-only", action="store_true", help="refuse PUT/DELETE/MKDIR/MOVE")
    parser.add_argument("--max-clients", type=int, default=DEFAULT_MAX_CLIENTS)
    parser.add_argument(
        "--rate-limit", type=int, default=0, help="requests per 10s per connection (0 = off)"
    )
    parser.add_argument("--max-upload", type=int, default=8192, help="largest upload, in MB")
    parser.add_argument("--new-code", action="store_true", help="rotate the pairing code")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--no-color", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    term.init_color(not args.no_color)
    identity = ServerIdentity.load_or_create(rotate_code=args.new_code)
    if args.new_code:
        term.ok(f"new pairing code: {identity.code}")
        term.hint("clients paired with the old code must pair again")
    return serve(Config(args, identity))
