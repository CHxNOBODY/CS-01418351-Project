"""The KUFT/2.0 client: pairing, the interactive shell, and one-shot transfers.

Trust works like SSH.  The first time you meet a server you confirm it with the
pairing code it printed; the client stores the certificate fingerprint and the
key derived from that code, and every later connection is silent.  If the
fingerprint ever changes, the client stops rather than asking -- a changed
fingerprint on a pinned host is the exact signature of a machine-in-the-middle.
"""

from __future__ import annotations

import argparse
import getpass
import hmac
import os
import shlex
import socket
import ssl
import sys
from pathlib import Path

from . import term
from .crypto import (
    KnownHosts,
    b64,
    client_proof,
    derive_auth_key,
    format_fingerprint,
    cert_fingerprint,
    new_nonce,
    normalize_code,
    server_proof,
    unb64,
)
from .protocol import (
    Reader,
    Request,
    Response,
    Writer,
    ProtocolError,
    body_length,
    checksum_file,
)

DEFAULT_PORT = 5150


class TransferError(Exception):
    """A request completed but the answer was not what we wanted."""


class FingerprintChanged(Exception):
    """The pinned certificate no longer matches.  Never auto-recoverable."""


class Client:
    def __init__(
        self,
        host: str,
        port: int,
        *,
        downloads: Path,
        known_hosts: KnownHosts | None = None,
        quiet: bool = False,
    ):
        self.host = host
        self.port = port
        self.downloads = downloads
        self.known_hosts = known_hosts or KnownHosts()
        self.quiet = quiet
        self.remote_cwd = "/"
        self.conn: ssl.SSLSocket | None = None
        self.stream = None
        self.reader: Reader | None = None
        self.writer: Writer | None = None
        self.fingerprint = b""
        self.server_info: dict[str, str] = {}
        self.read_only = False

    # ------------------------------------------------------------- connect

    def connect(self, *, code: str | None = None) -> None:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        # We pin the exact certificate ourselves, so the CA machinery and
        # hostname matching would only get in the way of a self-signed peer.
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        raw = socket.create_connection((self.host, self.port), timeout=20)
        raw.settimeout(300)
        self.conn = ctx.wrap_socket(raw, server_hostname=self.host)
        der = self.conn.getpeercert(binary_form=True)
        if not der:
            raise TransferError("server presented no certificate")
        self.fingerprint = cert_fingerprint(der)

        self.stream = self.conn.makefile("rwb")
        self.reader = Reader(self.stream)
        self.writer = Writer(self.stream)

        if not self.quiet:
            local = self.conn.getsockname()
            term.info(
                f"connected to {term.paint(f'{self.host}:{self.port}', 'bold')} "
                f"from {local[0]}:{local[1]}  "
                f"{term.paint(self.conn.version() or '', 'green')}"
            )

        hello = self.request(Request("HELLO", "*"))
        if not hello.ok:
            raise TransferError(f"HELLO refused: {hello.code} {hello.detail}")
        self.server_info = hello.headers
        self.read_only = hello.headers.get("read-only") == "true"

        self.authenticate(hello, code=code)

    def authenticate(self, hello: Response, *, code: str | None) -> None:
        """Prove we know the pairing code, and make the server prove it too."""
        record = self.known_hosts.get(self.host, self.port)

        if record and not hmac.compare_digest(record.fingerprint, self.fingerprint):
            raise FingerprintChanged(
                "the certificate for this server has CHANGED.\n"
                f"    pinned now : {format_fingerprint(record.fingerprint)}\n"
                f"    offered    : {format_fingerprint(self.fingerprint)}\n"
                "    Someone may be intercepting the connection. If you know the\n"
                "    server was rebuilt, run:  python kuft.py forget "
                f"{self.host} --port {self.port}"
            )

        if record:
            auth_key = record.auth_key
            first_time = False
        else:
            first_time = True
            if code is None:
                code = self._prompt_for_code()
            try:
                salt = unb64(hello.headers.get("salt", ""))
            except ValueError:
                raise TransferError("server sent a malformed salt") from None
            if len(salt) < 8:
                raise TransferError("server sent no usable salt")
            if not self.quiet:
                term.info("    deriving key from pairing code...")
            auth_key = derive_auth_key(code, salt)

        try:
            s_nonce = unb64(hello.headers.get("nonce", ""))
        except ValueError:
            raise TransferError("server sent a malformed nonce") from None
        if len(s_nonce) < 16:
            raise TransferError("server sent no usable nonce")

        c_nonce = new_nonce()
        proof = client_proof(auth_key, self.fingerprint, c_nonce, s_nonce)
        resp = self.request(
            Request("AUTH", "*", {"nonce": b64(c_nonce), "proof": b64(proof)})
        )

        if resp.code == 401:
            raise TransferError(
                "pairing failed -- that code does not match this server.\n"
                "    Check the code shown in the server's window (it is case-insensitive)."
            )
        if not resp.ok:
            raise TransferError(f"AUTH failed: {resp.code} {resp.detail}")

        # The server proves it holds the same key.  Without this check a fake
        # server could accept any proof and then feed us fabricated files.
        try:
            got = unb64(resp.headers.get("proof", ""))
        except ValueError:
            raise TransferError("server sent a malformed proof") from None
        expect = server_proof(auth_key, self.fingerprint, c_nonce, s_nonce)
        if not hmac.compare_digest(expect, got):
            raise TransferError(
                "the server failed to prove it knows the pairing code -- "
                "refusing to continue"
            )

        # The share name is only disclosed after authentication, so it arrives
        # on the AUTH reply rather than on HELLO.  Fold it in.
        for key in ("share",):
            if key in resp.headers:
                self.server_info[key] = resp.headers[key]

        if first_time:
            self.known_hosts.remember(self.host, self.port, self.fingerprint, auth_key)
            if not self.quiet:
                term.ok(f"paired with {self.host}:{self.port}")
                term.hint(f"fingerprint {format_fingerprint(self.fingerprint)} pinned; no code needed next time")
        elif not self.quiet:
            term.ok(f"authenticated (fingerprint matches the pinned one)")

    def _prompt_for_code(self) -> str:
        term.rule("first connection to this server")
        term.info(
            f"    Fingerprint offered: {term.paint(format_fingerprint(self.fingerprint), 'bold')}"
        )
        term.hint("Check it matches the one printed by the server, then type its pairing code.")
        while True:
            try:
                entered = getpass.getpass("    pairing code: ")
            except (EOFError, KeyboardInterrupt):
                raise TransferError("pairing cancelled") from None
            try:
                normalize_code(entered)
                return entered
            except ValueError as exc:
                term.warn(str(exc))

    def close(self) -> None:
        try:
            if self.writer:
                self.request(Request("QUIT", "*"))
        except (OSError, ProtocolError, ConnectionError):
            pass
        for closeable in (self.stream, self.conn):
            try:
                if closeable:
                    closeable.close()
            except OSError:
                pass

    # ------------------------------------------------------------- requests

    def request(self, request: Request, body: bytes = b"") -> Response:
        """Send a control request and read the whole reply into memory."""
        assert self.writer and self.reader
        self.writer.send_bytes(request, body)
        resp = self.reader.read_response()
        resp.body = self.reader.drain_body(resp.headers)  # type: ignore[attr-defined]
        return resp

    def _remote(self, target: str) -> str:
        """Resolve a user-typed path against the remote working directory."""
        if not target:
            return self.remote_cwd
        if target.startswith("/"):
            return target
        base = self.remote_cwd.rstrip("/")
        return f"{base}/{target}" if base else f"/{target}"

    # ------------------------------------------------------------ transfers

    def download(self, target: str, save_as: str | None = None, *, resume: bool = True) -> Path:
        remote = self._remote(target)
        name = save_as or Path(remote).name
        destination = self.downloads / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        partial = destination.with_suffix(destination.suffix + ".part")

        offset = partial.stat().st_size if (resume and partial.exists()) else 0
        headers = {"range": str(offset)} if offset else {}
        if offset:
            term.info(f"    resuming at {term.human_bytes(offset)}")

        assert self.writer and self.reader
        self.writer.send_bytes(Request("GET", remote, headers), b"")
        resp = self.reader.read_response()

        if not resp.ok:
            self.reader.drain_body(resp.headers)
            raise TransferError(f"{resp.code} {resp.phrase} -- {resp.detail}")

        total = body_length(resp.headers)
        progress = term.Progress(f"down {name}", total, quiet=self.quiet)
        mode = "r+b" if offset and partial.exists() else "wb"
        try:
            with open(partial, mode) as handle:
                if offset:
                    handle.seek(offset)
                written, digest = self.reader.pipe_body(
                    resp.headers, handle, on_progress=progress.update
                )
            progress.finish()
        except BaseException:
            # Leave the .part file behind on purpose -- that is what makes the
            # next attempt resumable instead of starting over.
            print()
            raise

        claimed = resp.headers.get("checksum")
        if claimed and claimed != digest:
            raise TransferError(
                f"checksum mismatch on the received window -- {name} left as .part"
            )

        whole = resp.headers.get("whole-checksum")
        if whole:
            actual = checksum_file(partial)
            if actual != whole:
                raise TransferError(
                    f"assembled file does not match the server's checksum -- "
                    f"{name} left as .part"
                )

        os.replace(partial, destination)
        term.status_line(resp.code, resp.phrase, resp.detail)
        if not self.quiet:
            term.hint(f"saved to {destination}")
            if whole:
                term.hint(f"checksum verified {whole[:30]}...")
        return destination

    def upload(
        self,
        local: str,
        save_as: str | None = None,
        *,
        overwrite: bool = False,
        corrupt: bool = False,
    ) -> Response:
        source = Path(local).expanduser()
        if not source.is_file():
            raise TransferError(f"no such local file: {source}")

        name = save_as or source.name
        remote = self._remote(name)
        size = source.stat().st_size

        # Ask before sending.  Without this the whole payload goes up the wire
        # and is only then refused with 409 -- painful on a 40 GB file over a
        # slow link.  One extra round trip is the cheaper trade.
        if not overwrite:
            probe = self.request(Request("STAT", remote))
            if probe.ok:
                raise TransferError(
                    f"{remote} already exists on the server "
                    f"({term.human_bytes(int(probe.headers.get('size', 0)))}) -- "
                    "add --force to replace it"
                )

        digest = checksum_file(source)
        if corrupt:
            # Deliberately wrong, to demonstrate the server's 422 path.
            digest = "sha256=" + "0" * 64

        headers = {
            "content-type": "application/octet-stream",
            "checksum": digest,
            "overwrite": "true" if overwrite else "false",
        }
        progress = term.Progress(f"up {name}", size, quiet=self.quiet)
        assert self.writer and self.reader
        with open(source, "rb") as handle:
            self.writer.send_stream(
                Request("PUT", remote, headers), handle, size, on_progress=progress.update
            )
        progress.finish()

        resp = self.reader.read_response()
        self.reader.drain_body(resp.headers)
        term.status_line(resp.code, resp.phrase, resp.detail)
        if not resp.ok:
            raise TransferError(f"{resp.code} {resp.phrase} -- {resp.detail}")
        return resp


# ------------------------------------------------------------------- the shell

HELP = """
  Remote                                Local
    ls [dir]        list a directory      lls [dir]     list a local directory
    cd <dir>        change remote dir     lcd <dir>     change local dir
    pwd             show remote dir       lpwd          show local dir
    stat <file>     size + checksum
    get <f> [as]    download (resumable)
    put <f> [as]    upload
    mkdir <dir>     create a directory
    rm <path>       delete a file or empty dir
    mv <a> <b>      rename or move

  Session
    info            server, TLS and fingerprint details
    help            this list
    quit            close politely and exit

  Overwrite an existing remote file with:   put <file> --force
"""


class Shell:
    def __init__(self, client: Client):
        self.client = client
        self.running = True

    def run(self) -> int:
        term.rule("connected")
        info = self.client.server_info
        term.info(
            f"    {info.get('server', 'kuft')}   share: {term.paint(info.get('share', '?'), 'bold')}"
            + (term.paint("   READ-ONLY", "yellow") if self.client.read_only else "")
        )
        term.hint("type 'help' for commands, 'quit' to leave")
        print()

        while self.running:
            try:
                prompt = term.paint(f"kuft {self.client.remote_cwd}> ", "cyan", "bold")
                line = input(prompt)
            except (EOFError, KeyboardInterrupt):
                print()
                break
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                self.execute(line)
            except TransferError as exc:
                term.fail(str(exc))
            except ProtocolError as exc:
                term.fail(f"protocol error {exc.code}: {exc.detail}")
            except (ConnectionError, ssl.SSLError) as exc:
                term.fail(f"connection lost: {exc}")
                return 1
            except OSError as exc:
                term.fail(str(exc))
        return 0

    def execute(self, line: str) -> None:
        try:
            parts = shlex.split(line)
        except ValueError as exc:
            raise TransferError(f"could not parse that line: {exc}") from None
        command, args = parts[0].lower(), parts[1:]

        table = {
            "help": self.cmd_help,
            "?": self.cmd_help,
            "ls": self.cmd_ls,
            "list": self.cmd_ls,
            "dir": self.cmd_ls,
            "cd": self.cmd_cd,
            "pwd": self.cmd_pwd,
            "stat": self.cmd_stat,
            "get": self.cmd_get,
            "put": self.cmd_put,
            "rm": self.cmd_rm,
            "delete": self.cmd_rm,
            "mkdir": self.cmd_mkdir,
            "mv": self.cmd_mv,
            "move": self.cmd_mv,
            "lls": self.cmd_lls,
            "lcd": self.cmd_lcd,
            "lpwd": self.cmd_lpwd,
            "info": self.cmd_info,
            "quit": self.cmd_quit,
            "exit": self.cmd_quit,
            "bye": self.cmd_quit,
        }
        handler = table.get(command)
        if handler is None:
            raise TransferError(f"unknown command {command!r} -- try 'help'")
        handler(args)

    # ------------------------------------------------------------ commands

    def cmd_help(self, args: list[str]) -> None:
        print(HELP)

    def cmd_ls(self, args: list[str]) -> None:
        target = self.client._remote(args[0] if args else "")
        resp = self.client.request(Request("LIST", target))
        term.status_line(resp.code, resp.phrase, resp.detail)
        if not resp.ok:
            return
        body = getattr(resp, "body", b"").decode("utf-8", "replace")
        rows = []
        for row in body.splitlines():
            if not row.strip():
                continue
            kind, size, modified, name = row.split("\t", 3)
            rows.append(
                [
                    term.paint(kind, "blue" if kind == "DIR" else "grey"),
                    "-" if size == "-" else term.human_bytes(int(size)),
                    modified.replace("T", " ").rstrip("Z"),
                    term.paint(name, "bold") if kind == "DIR" else name,
                ]
            )
        term.table(["TYPE", "SIZE", "MODIFIED (UTC)", "NAME"], rows)

    def cmd_cd(self, args: list[str]) -> None:
        if not args:
            self.client.remote_cwd = "/"
            return
        target = self.client._remote(args[0])
        if args[0] == "..":
            target = "/" + "/".join(self.client.remote_cwd.strip("/").split("/")[:-1])
        resp = self.client.request(Request("LIST", target))
        if not resp.ok:
            term.status_line(resp.code, resp.phrase, resp.detail)
            return
        self.client.remote_cwd = "/" + resp.headers.get("path", "").strip("/")
        term.ok(f"remote directory is now {self.client.remote_cwd}")

    def cmd_pwd(self, args: list[str]) -> None:
        term.info(f"    {self.client.remote_cwd}")

    def cmd_stat(self, args: list[str]) -> None:
        if not args:
            raise TransferError("usage: stat <file>")
        resp = self.client.request(Request("STAT", self.client._remote(args[0])))
        term.status_line(resp.code, resp.phrase, resp.detail)
        if not resp.ok:
            return
        term.info(f"    kind      {resp.headers.get('kind', '?')}")
        term.info(f"    size      {term.human_bytes(int(resp.headers.get('size', 0)))}"
                  f"  ({resp.headers.get('size')} octets)")
        term.info(f"    modified  {resp.headers.get('modified', '?')}")
        if "checksum" in resp.headers:
            term.info(f"    checksum  {resp.headers['checksum']}")

    def cmd_get(self, args: list[str]) -> None:
        if not args:
            raise TransferError("usage: get <file> [save-as]")
        self.client.download(args[0], args[1] if len(args) > 1 else None)

    def cmd_put(self, args: list[str]) -> None:
        if not args:
            raise TransferError("usage: put <local-file> [remote-name] [--force]")
        flags = {a for a in args if a.startswith("--")}
        positional = [a for a in args if not a.startswith("--")]
        self.client.upload(
            positional[0],
            positional[1] if len(positional) > 1 else None,
            overwrite="--force" in flags,
            corrupt="--corrupt" in flags,
        )

    def cmd_rm(self, args: list[str]) -> None:
        if not args:
            raise TransferError("usage: rm <path>")
        resp = self.client.request(Request("DELETE", self.client._remote(args[0])))
        term.status_line(resp.code, resp.phrase, resp.detail)

    def cmd_mkdir(self, args: list[str]) -> None:
        if not args:
            raise TransferError("usage: mkdir <dir>")
        resp = self.client.request(Request("MKDIR", self.client._remote(args[0])))
        term.status_line(resp.code, resp.phrase, resp.detail)

    def cmd_mv(self, args: list[str]) -> None:
        if len(args) < 2:
            raise TransferError("usage: mv <source> <destination>")
        resp = self.client.request(
            Request(
                "MOVE",
                self.client._remote(args[0]),
                {"destination": self.client._remote(args[1])},
            )
        )
        term.status_line(resp.code, resp.phrase, resp.detail)

    def cmd_lls(self, args: list[str]) -> None:
        base = Path(args[0]).expanduser() if args else Path.cwd()
        if not base.is_dir():
            raise TransferError(f"not a local directory: {base}")
        rows = []
        for entry in sorted(base.iterdir(), key=lambda p: (p.is_file(), p.name.lower())):
            try:
                size = "-" if entry.is_dir() else term.human_bytes(entry.stat().st_size)
            except OSError:
                continue
            rows.append(["DIR" if entry.is_dir() else "FILE", size, entry.name])
        term.info(f"    {base}")
        term.table(["TYPE", "SIZE", "NAME"], rows)

    def cmd_lcd(self, args: list[str]) -> None:
        if not args:
            term.info(f"    {Path.cwd()}")
            return
        target = Path(args[0]).expanduser()
        if not target.is_dir():
            raise TransferError(f"not a local directory: {target}")
        os.chdir(target)
        term.ok(f"local directory is now {Path.cwd()}")

    def cmd_lpwd(self, args: list[str]) -> None:
        term.info(f"    {Path.cwd()}")

    def cmd_info(self, args: list[str]) -> None:
        client = self.client
        conn = client.conn
        cipher = conn.cipher() if conn else None
        rows = [
            ["server", client.server_info.get("server", "?")],
            ["address", f"{client.host}:{client.port}"],
            ["tls", conn.version() if conn else "?"],
            ["cipher", cipher[0] if cipher else "?"],
            ["fingerprint", format_fingerprint(client.fingerprint)],
            ["share", client.server_info.get("share", "?")],
            ["read-only", client.server_info.get("read-only", "?")],
            ["max upload", term.human_bytes(int(client.server_info.get("max-upload", 0)))],
            ["downloads", str(client.downloads)],
        ]
        term.table(["FIELD", "VALUE"], rows)

    def cmd_quit(self, args: list[str]) -> None:
        self.running = False


# ------------------------------------------------------------------ entry point


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="kuft.py connect", description="Connect to a KUFT/2.0 server."
    )
    parser.add_argument("host", help="server address, e.g. 192.168.1.42")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--downloads", default="downloads", help="where get saves files")
    parser.add_argument("--code", help="pairing code (otherwise prompted, hidden)")
    parser.add_argument("--get", metavar="FILE", help="download one file and exit")
    parser.add_argument("--put", metavar="FILE", help="upload one file and exit")
    parser.add_argument("--as", dest="save_as", metavar="NAME", help="name for --get/--put")
    parser.add_argument("--force", action="store_true", help="allow --put to overwrite")
    parser.add_argument("--ls", metavar="DIR", nargs="?", const="/", help="list and exit")
    parser.add_argument("--no-color", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    term.init_color(not args.no_color)

    downloads = Path(args.downloads).expanduser()
    downloads.mkdir(parents=True, exist_ok=True)
    one_shot = bool(args.get or args.put or args.ls)

    client = Client(args.host, args.port, downloads=downloads)
    try:
        client.connect(code=args.code)
    except FingerprintChanged as exc:
        term.fail("PINNED CERTIFICATE MISMATCH")
        print(f"    {exc}")
        return 2
    except TransferError as exc:
        term.fail(str(exc))
        return 1
    except ssl.SSLError as exc:
        term.fail(f"TLS handshake failed: {exc}")
        term.hint("is the other end really a KUFT/2.0 server?")
        return 1
    except OSError as exc:
        term.fail(f"cannot reach {args.host}:{args.port} -- {exc.strerror or exc}")
        term.hint("check the address, that the server is running, and the firewall")
        return 1

    shell = Shell(client)
    try:
        if one_shot:
            if args.ls:
                shell.cmd_ls([args.ls])
            if args.get:
                client.download(args.get, args.save_as)
            if args.put:
                client.upload(args.put, args.save_as, overwrite=args.force)
            return 0
        return shell.run()
    except TransferError as exc:
        term.fail(str(exc))
        return 1
    finally:
        client.close()
        if not one_shot:
            term.info(term.paint("disconnected", "grey"))
