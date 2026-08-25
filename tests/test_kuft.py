"""Automated tests for KUFT/2.0.

Three layers:

*   ``ProtocolTests`` -- the codec alone, no sockets.
*   ``CryptoTests`` -- pairing codes, key derivation, proofs, known hosts.
*   ``EndToEndTests`` and friends -- a real TLS server on an ephemeral port,
    driven by the real client over a real connection.

Everything runs against a temporary ``KUFT_HOME``, so running the suite never
touches the keys or known-hosts file belonging to the person running it.

    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import io
import os
import socket
import sys
import tempfile
import types
import threading
import time
import unittest
from argparse import Namespace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

os.environ.setdefault("KUFT_NO_REEXEC", "1")
_TEST_HOME = tempfile.mkdtemp(prefix="kuft-test-home-")
os.environ["KUFT_HOME"] = _TEST_HOME

from kuft import crypto, protocol, server as server_mod, term  # noqa: E402
from kuft.client import Client, FingerprintChanged, TransferError  # noqa: E402
from kuft.protocol import ProtocolError, Reader, Request, Response, Writer  # noqa: E402


# --------------------------------------------------------------------- codec


class ProtocolTests(unittest.TestCase):
    def roundtrip_request(self, request: Request) -> Request:
        reader = Reader(io.BytesIO(request.head_bytes()))
        return reader.read_request()

    def test_request_roundtrip(self):
        got = self.roundtrip_request(Request("GET", "/notes.md", {"range": "12"}))
        self.assertEqual(got.method, "GET")
        self.assertEqual(got.target, "/notes.md")
        self.assertEqual(got.headers["range"], "12")

    def test_target_with_spaces_survives(self):
        """The bug percent-encoding exists to prevent."""
        name = "/Quarterly Report (final).pdf"
        self.assertEqual(self.roundtrip_request(Request("GET", name)).target, name)

    def test_target_with_unicode_survives(self):
        name = "/รายงาน ผลลัพธ์ 2569.txt"
        self.assertEqual(self.roundtrip_request(Request("PUT", name)).target, name)

    def test_response_roundtrip(self):
        head = Response(206, {"detail": "partial", "offset": "40"}).head_bytes()
        got = Reader(io.BytesIO(head)).read_response()
        self.assertEqual(got.code, 206)
        self.assertEqual(got.phrase, "PARTIAL CONTENT")
        self.assertEqual(got.headers["offset"], "40")
        self.assertTrue(got.ok, "206 is a 2xx, so it counts as success")
        self.assertFalse(Response(404).ok)

    def test_body_may_contain_crlf_and_nul(self):
        payload = b"line\r\nline\x00\x00\r\n\r\nmore"
        buffer = io.BytesIO()
        Writer(buffer).send_bytes(Response(200), payload)
        buffer.seek(0)
        reader = Reader(buffer)
        resp = reader.read_response()
        self.assertEqual(reader.drain_body(resp.headers), payload)

    def test_back_to_back_messages_stay_framed(self):
        buffer = io.BytesIO()
        writer = Writer(buffer)
        writer.send_bytes(Request("PUT", "/a.txt"), b"AAA")
        writer.send_bytes(Request("PUT", "/b.txt"), b"BBBB")
        buffer.seek(0)
        reader = Reader(buffer)
        first = reader.read_request()
        self.assertEqual(reader.drain_body(first.headers), b"AAA")
        second = reader.read_request()
        self.assertEqual(second.target, "/b.txt")
        self.assertEqual(reader.drain_body(second.headers), b"BBBB")

    def test_streamed_body_hashes_what_it_wrote(self):
        payload = os.urandom(300_000)
        buffer = io.BytesIO()
        Writer(buffer).send_stream(Response(200), io.BytesIO(payload), len(payload))
        buffer.seek(0)
        reader = Reader(buffer)
        resp = reader.read_response()
        sink = io.BytesIO()
        written, digest = reader.pipe_body(resp.headers, sink)
        self.assertEqual(written, len(payload))
        self.assertEqual(sink.getvalue(), payload)
        self.assertEqual(digest, protocol.checksum_bytes(payload))

    def test_truncated_body_is_rejected(self):
        raw = Response(200, {"content-length": "100"}).head_bytes() + b"short"
        reader = Reader(io.BytesIO(raw))
        resp = reader.read_response()
        with self.assertRaises(ProtocolError):
            reader.drain_body(resp.headers)

    def test_unknown_method_is_405(self):
        raw = b"TELEPORT /x KUFT/2.0\r\n\r\n"
        with self.assertRaises(ProtocolError) as ctx:
            Reader(io.BytesIO(raw)).read_request()
        self.assertEqual(ctx.exception.code, 405)

    def test_wrong_version_is_505(self):
        raw = b"GET /x KUFT/9.9\r\n\r\n"
        with self.assertRaises(ProtocolError) as ctx:
            Reader(io.BytesIO(raw)).read_request()
        self.assertEqual(ctx.exception.code, 505)

    def test_malformed_request_line_is_400(self):
        with self.assertRaises(ProtocolError) as ctx:
            Reader(io.BytesIO(b"GET\r\n\r\n")).read_request()
        self.assertEqual(ctx.exception.code, 400)

    def test_line_without_crlf_is_400(self):
        with self.assertRaises(ProtocolError) as ctx:
            Reader(io.BytesIO(b"GET /x KUFT/2.0\n\n")).read_request()
        self.assertEqual(ctx.exception.code, 400)

    def test_overlong_line_is_400(self):
        raw = b"GET /" + b"a" * (protocol.MAX_LINE + 10) + b" KUFT/2.0\r\n\r\n"
        with self.assertRaises(ProtocolError) as ctx:
            Reader(io.BytesIO(raw)).read_request()
        self.assertEqual(ctx.exception.code, 400)

    def test_too_many_headers_is_400(self):
        head = b"GET /x KUFT/2.0\r\n"
        head += b"".join(
            f"h{i}: v\r\n".encode() for i in range(protocol.MAX_HEADERS + 5)
        )
        with self.assertRaises(ProtocolError) as ctx:
            Reader(io.BytesIO(head + b"\r\n")).read_request()
        self.assertEqual(ctx.exception.code, 400)

    def test_negative_content_length_is_400(self):
        with self.assertRaises(ProtocolError):
            protocol.body_length({"content-length": "-5"})

    def test_header_with_newline_is_refused_at_encode(self):
        with self.assertRaises(ValueError):
            Response(200, {"detail": "a\r\nInjected: yes"}).head_bytes()

    def test_closed_stream_raises_connection_error(self):
        with self.assertRaises(ConnectionError):
            Reader(io.BytesIO(b"")).read_line()


# -------------------------------------------------------------------- crypto


class CryptoTests(unittest.TestCase):
    def test_generated_code_normalizes_to_itself(self):
        code = crypto.generate_code()
        self.assertEqual(len(crypto.normalize_code(code)), crypto.CODE_CHARS)

    def test_code_is_case_and_dash_insensitive(self):
        code = crypto.generate_code()
        messy = code.lower().replace("-", " ")
        self.assertEqual(crypto.normalize_code(messy), crypto.normalize_code(code))

    def test_confusable_characters_are_repaired(self):
        self.assertEqual(crypto.normalize_code("0000-1111-8888"), "OOOOIIIIBBBB")

    def test_wrong_length_code_is_rejected(self):
        with self.assertRaises(ValueError):
            crypto.normalize_code("ABCD-EFGH")

    def test_derived_key_depends_on_salt(self):
        code = crypto.generate_code()
        a = crypto.derive_auth_key(code, b"salt-one-value!!")
        b = crypto.derive_auth_key(code, b"salt-two-value!!")
        self.assertEqual(len(a), crypto.KEY_BYTES)
        self.assertNotEqual(a, b)

    def test_proof_is_bound_to_the_fingerprint(self):
        """Change the certificate and the same code yields a different proof.

        This is the property that defeats a relaying attacker.
        """
        key = crypto.derive_auth_key(crypto.generate_code(), b"0123456789abcdef")
        c_nonce, s_nonce = crypto.new_nonce(), crypto.new_nonce()
        real = crypto.client_proof(key, b"\x01" * 32, c_nonce, s_nonce)
        forged = crypto.client_proof(key, b"\x02" * 32, c_nonce, s_nonce)
        self.assertNotEqual(real, forged)

    def test_client_and_server_proofs_differ(self):
        key = crypto.derive_auth_key(crypto.generate_code(), b"0123456789abcdef")
        fp, cn, sn = b"\x03" * 32, crypto.new_nonce(), crypto.new_nonce()
        self.assertNotEqual(
            crypto.client_proof(key, fp, cn, sn), crypto.server_proof(key, fp, cn, sn)
        )

    def test_proof_changes_with_nonce(self):
        key = crypto.derive_auth_key(crypto.generate_code(), b"0123456789abcdef")
        fp = b"\x04" * 32
        first = crypto.client_proof(key, fp, crypto.new_nonce(), b"s" * 32)
        second = crypto.client_proof(key, fp, crypto.new_nonce(), b"s" * 32)
        self.assertNotEqual(first, second)

    def test_identity_is_stable_across_loads(self):
        with tempfile.TemporaryDirectory() as home:
            first = crypto.ServerIdentity.load_or_create(Path(home))
            second = crypto.ServerIdentity.load_or_create(Path(home))
            self.assertEqual(first.fingerprint, second.fingerprint)
            self.assertEqual(first.code, second.code)

    def test_rotating_the_code_keeps_the_certificate(self):
        with tempfile.TemporaryDirectory() as home:
            first = crypto.ServerIdentity.load_or_create(Path(home))
            rotated = crypto.ServerIdentity.load_or_create(Path(home), rotate_code=True)
            self.assertEqual(first.fingerprint, rotated.fingerprint)
            self.assertNotEqual(first.code, rotated.code)
            self.assertNotEqual(first.auth_key, rotated.auth_key)

    def test_known_hosts_roundtrip(self):
        with tempfile.TemporaryDirectory() as home:
            path = Path(home) / "kh.json"
            hosts = crypto.KnownHosts(path)
            hosts.remember("1.2.3.4", 5150, b"\x05" * 32, b"\x06" * 32)
            reloaded = crypto.KnownHosts(path)
            record = reloaded.get("1.2.3.4", 5150)
            self.assertIsNotNone(record)
            self.assertEqual(record.fingerprint, b"\x05" * 32)
            self.assertTrue(reloaded.forget("1.2.3.4", 5150))
            self.assertIsNone(crypto.KnownHosts(path).get("1.2.3.4", 5150))

    def test_fingerprint_formatting_is_readable(self):
        pretty = crypto.format_fingerprint(b"\x07" * 32)
        self.assertEqual(len(pretty.split("-")), 6)


# --------------------------------------------------------------- code prompt


class SecretPromptTests(unittest.TestCase):
    """The pairing-code prompt has to work in every terminal, not just conhost.

    ``getpass`` reads the Windows console device directly and ignores stdin,
    so under mintty, Git Bash or an IDE terminal it waits forever for
    keystrokes that cannot arrive.  These pin down both halves of the
    replacement: the masked reader, and the fallback that keeps a terminal
    without a console usable.
    """

    def _masked(self, keys):
        """Run the masked reader against a scripted keyboard."""
        fake = types.ModuleType("msvcrt")
        pending = iter(keys)
        fake.getwch = lambda: next(pending)
        screen = io.StringIO()
        saved_msvcrt = sys.modules.get("msvcrt")
        saved_stdout = sys.stdout
        sys.modules["msvcrt"] = fake
        sys.stdout = screen
        try:
            return term._read_masked_windows("code: "), screen.getvalue()
        finally:
            sys.stdout = saved_stdout
            if saved_msvcrt is None:
                sys.modules.pop("msvcrt", None)
            else:
                sys.modules["msvcrt"] = saved_msvcrt

    def test_masked_read_returns_what_was_typed(self):
        value, screen = self._masked(list("6AOS-OUBQ-TCLO") + ["\r"])
        self.assertEqual(value, "6AOS-OUBQ-TCLO")
        self.assertNotIn("6AOS", screen)

    def test_masked_read_echoes_one_star_per_character(self):
        _, screen = self._masked(list("ABC") + ["\r"])
        self.assertEqual(screen.count("*"), 3)

    def test_masked_read_accepts_line_feed_as_enter(self):
        value, _ = self._masked(list("AB") + ["\n"])
        self.assertEqual(value, "AB")

    def test_masked_read_handles_backspace(self):
        value, _ = self._masked(list("AB") + ["\b"] + list("C") + ["\r"])
        self.assertEqual(value, "AC")

    def test_backspace_on_empty_input_is_harmless(self):
        value, _ = self._masked(["\b", "\b", "\r"])
        self.assertEqual(value, "")

    def test_arrow_and_function_keys_are_discarded(self):
        for prefix in ("\x00", "\xe0"):
            with self.subTest(prefix=prefix):
                value, _ = self._masked(list("A") + [prefix, "K"] + list("B") + ["\r"])
                self.assertEqual(value, "AB")

    def test_ctrl_c_and_ctrl_z_cancel(self):
        with self.assertRaises(KeyboardInterrupt):
            self._masked(list("AB") + ["\x03"])
        with self.assertRaises(EOFError):
            self._masked(list("AB") + ["\x1a"])

    def test_falls_back_to_stdin_when_no_console_is_available(self):
        """The regression: a terminal without a console must still be typable."""
        saved_stdin, saved_stdout = sys.stdin, sys.stdout
        saved_probe = term.can_hide_input
        term.can_hide_input = lambda: False
        sys.stdin = io.StringIO("6AOS-OUBQ-TCLO\n")
        sys.stdout = io.StringIO()
        try:
            self.assertEqual(term.read_secret("code: "), "6AOS-OUBQ-TCLO")
            self.assertIn("code: ", sys.stdout.getvalue())
        finally:
            term.can_hide_input = saved_probe
            sys.stdin, sys.stdout = saved_stdin, saved_stdout

    def test_fallback_strips_a_windows_line_ending(self):
        saved_stdin, saved_stdout = sys.stdin, sys.stdout
        saved_probe = term.can_hide_input
        term.can_hide_input = lambda: False
        sys.stdin = io.StringIO("ABCD\r\n")
        sys.stdout = io.StringIO()
        try:
            self.assertEqual(term.read_secret("code: "), "ABCD")
        finally:
            term.can_hide_input = saved_probe
            sys.stdin, sys.stdout = saved_stdin, saved_stdout

    def test_closed_input_raises_rather_than_hanging(self):
        saved_stdin, saved_stdout = sys.stdin, sys.stdout
        saved_probe = term.can_hide_input
        term.can_hide_input = lambda: False
        sys.stdin = io.StringIO("")
        sys.stdout = io.StringIO()
        try:
            with self.assertRaises(EOFError):
                term.read_secret("code: ")
        finally:
            term.can_hide_input = saved_probe
            sys.stdin, sys.stdout = saved_stdin, saved_stdout

    def test_console_probe_never_raises(self):
        self.assertIn(term.can_hide_input(), (True, False))


# ------------------------------------------------------------------- harness


class ServerHarness:
    """A real KUFT server on an ephemeral port, for the duration of a test."""

    def __init__(self, share: Path, **overrides):
        self.share = share
        self.port = self._free_port()
        self.identity = crypto.ServerIdentity.load_or_create()
        args = Namespace(
            host="127.0.0.1",
            port=self.port,
            share=str(share),
            read_only=overrides.get("read_only", False),
            max_clients=overrides.get("max_clients", 8),
            rate_limit=overrides.get("rate_limit", 0),
            max_upload=overrides.get("max_upload", 64),
            verbose=False,
        )
        self.cfg = server_mod.Config(args, self.identity)
        self.thread: threading.Thread | None = None

    @staticmethod
    def _free_port() -> int:
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            return probe.getsockname()[1]

    def start(self) -> None:
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.3):
                    return
            except OSError:
                time.sleep(0.05)
        raise RuntimeError("server did not come up")

    def _run(self) -> None:
        # serve() prints a banner; tests do not need it on screen.
        stdout, sys.stdout = sys.stdout, io.StringIO()
        try:
            server_mod.serve(self.cfg)
        except Exception:
            pass
        finally:
            sys.stdout = stdout


class E2EBase(unittest.TestCase):
    read_only = False
    rate_limit = 0
    max_clients = 8

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="kuft-e2e-")
        root = Path(cls.tmp.name)
        cls.share = root / "share"
        cls.downloads = root / "downloads"
        cls.outbox = root / "outbox"
        for folder in (cls.share, cls.downloads, cls.outbox):
            folder.mkdir(parents=True)

        (cls.share / "readme.txt").write_text("hello from the server\n", encoding="utf-8")
        (cls.share / "unicode.txt").write_text("สวัสดี world\n", encoding="utf-8")
        (cls.share / "blob.bin").write_bytes(os.urandom(400_000))
        (cls.share / "sub").mkdir()
        (cls.share / "sub" / "inner.txt").write_text("inner\n", encoding="utf-8")
        (cls.outbox / "upload.txt").write_text("client payload\n", encoding="utf-8")
        (cls.outbox / "blob2.bin").write_bytes(os.urandom(250_000))

        cls.harness = ServerHarness(
            cls.share,
            read_only=cls.read_only,
            rate_limit=cls.rate_limit,
            max_clients=cls.max_clients,
        )
        cls.harness.start()
        cls.code = cls.harness.identity.code

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def make_client(self, *, fresh_hosts: bool = True) -> Client:
        hosts_path = Path(self.tmp.name) / f"known-{os.urandom(4).hex()}.json"
        client = Client(
            "127.0.0.1",
            self.harness.port,
            downloads=self.downloads,
            known_hosts=crypto.KnownHosts(hosts_path)
            if fresh_hosts
            else crypto.KnownHosts(),
            quiet=True,
        )
        return client

    def connected(self, **kwargs) -> Client:
        client = self.make_client(**kwargs)
        client.connect(code=self.code)
        self.addCleanup(client.close)
        return client


# ---------------------------------------------------------------- end to end


class EndToEndTests(E2EBase):
    def test_tls13_and_pairing(self):
        client = self.connected()
        self.assertEqual(client.conn.version(), "TLSv1.3")
        self.assertEqual(len(client.fingerprint), 32)

    def test_wrong_code_is_rejected(self):
        client = self.make_client()
        self.addCleanup(client.close)
        wrong = crypto.generate_code()
        while wrong == self.code:
            wrong = crypto.generate_code()
        with self.assertRaises(TransferError) as ctx:
            client.connect(code=wrong)
        self.assertIn("does not match", str(ctx.exception))

    def test_second_connection_needs_no_code(self):
        hosts = crypto.KnownHosts(Path(self.tmp.name) / "sticky.json")
        first = Client("127.0.0.1", self.harness.port, downloads=self.downloads,
                       known_hosts=hosts, quiet=True)
        first.connect(code=self.code)
        first.close()

        second = Client("127.0.0.1", self.harness.port, downloads=self.downloads,
                        known_hosts=hosts, quiet=True)
        second.connect()  # no code supplied at all
        self.addCleanup(second.close)
        self.assertTrue(second.server_info)

    def test_changed_fingerprint_aborts(self):
        hosts = crypto.KnownHosts(Path(self.tmp.name) / "tampered.json")
        hosts.remember("127.0.0.1", self.harness.port, b"\xff" * 32, b"\x00" * 32)
        client = Client("127.0.0.1", self.harness.port, downloads=self.downloads,
                        known_hosts=hosts, quiet=True)
        self.addCleanup(client.close)
        with self.assertRaises(FingerprintChanged):
            client.connect(code=self.code)

    def test_unauthenticated_request_is_401(self):
        """Skip AUTH entirely and try to move data."""
        client = self.make_client()
        self.addCleanup(client.close)
        import ssl

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        raw = socket.create_connection(("127.0.0.1", self.harness.port), timeout=10)
        conn = ctx.wrap_socket(raw, server_hostname="127.0.0.1")
        stream = conn.makefile("rwb")
        Writer(stream).send_bytes(Request("HELLO", "*"), b"")
        reader = Reader(stream)
        reader.drain_body(reader.read_response().headers)
        Writer(stream).send_bytes(Request("LIST", "/"), b"")
        resp = reader.read_response()
        reader.drain_body(resp.headers)
        conn.close()
        self.assertEqual(resp.code, 401)

    def test_list(self):
        client = self.connected()
        resp = client.request(Request("LIST", "/"))
        self.assertEqual(resp.code, 200)
        names = [row.split("\t")[3] for row in resp.body.decode().splitlines()]
        self.assertIn("readme.txt", names)
        self.assertIn("sub", names)

    def test_list_missing_directory_is_404(self):
        client = self.connected()
        self.assertEqual(client.request(Request("LIST", "/nope")).code, 404)

    def test_stat_reports_checksum(self):
        client = self.connected()
        resp = client.request(Request("STAT", "/readme.txt"))
        self.assertEqual(resp.code, 200)
        self.assertEqual(
            resp.headers["checksum"], protocol.checksum_file(self.share / "readme.txt")
        )

    def test_stat_missing_is_404(self):
        client = self.connected()
        self.assertEqual(client.request(Request("STAT", "/ghost")).code, 404)

    def test_download_text(self):
        client = self.connected()
        path = client.download("/readme.txt")
        self.assertEqual(path.read_text(encoding="utf-8"), "hello from the server\n")

    def test_download_unicode_content(self):
        client = self.connected()
        path = client.download("/unicode.txt")
        self.assertEqual(path.read_text(encoding="utf-8"), "สวัสดี world\n")

    def test_download_binary_matches_byte_for_byte(self):
        client = self.connected()
        path = client.download("/blob.bin")
        self.assertEqual(path.read_bytes(), (self.share / "blob.bin").read_bytes())

    def test_download_under_a_different_name(self):
        client = self.connected()
        path = client.download("/readme.txt", "renamed.txt")
        self.assertEqual(path.name, "renamed.txt")
        self.assertTrue(path.exists())

    def test_download_missing_file_is_404(self):
        client = self.connected()
        with self.assertRaises(TransferError) as ctx:
            client.download("/ghost.txt")
        self.assertIn("404", str(ctx.exception))

    def test_resume_completes_the_file(self):
        """Pre-seed a .part file; the client must ask for the remainder only."""
        client = self.connected()
        source = (self.share / "blob.bin").read_bytes()
        partial = self.downloads / "resumed.bin.part"
        partial.write_bytes(source[:150_000])

        path = client.download("/blob.bin", "resumed.bin")
        self.assertEqual(path.read_bytes(), source)

    def test_upload_creates_201(self):
        client = self.connected()
        resp = client.upload(str(self.outbox / "upload.txt"), "fresh.txt")
        self.assertEqual(resp.code, 201)
        self.assertEqual(
            (self.share / "fresh.txt").read_text(encoding="utf-8"), "client payload\n"
        )

    def test_upload_binary_matches(self):
        client = self.connected()
        client.upload(str(self.outbox / "blob2.bin"), "blob2.bin")
        self.assertEqual(
            (self.share / "blob2.bin").read_bytes(),
            (self.outbox / "blob2.bin").read_bytes(),
        )

    def test_upload_over_existing_without_force_is_refused(self):
        client = self.connected()
        client.upload(str(self.outbox / "upload.txt"), "dup.txt")
        with self.assertRaises(TransferError) as ctx:
            client.upload(str(self.outbox / "upload.txt"), "dup.txt")
        self.assertIn("already exists", str(ctx.exception))

    def test_upload_with_force_replaces(self):
        client = self.connected()
        client.upload(str(self.outbox / "upload.txt"), "replaceme.txt")
        resp = client.upload(
            str(self.outbox / "upload.txt"), "replaceme.txt", overwrite=True
        )
        self.assertEqual(resp.code, 200)

    def test_bad_checksum_is_422_and_leaves_nothing_behind(self):
        client = self.connected()
        with self.assertRaises(TransferError) as ctx:
            client.upload(str(self.outbox / "upload.txt"), "corrupt.txt", corrupt=True)
        self.assertIn("422", str(ctx.exception))
        self.assertFalse((self.share / "corrupt.txt").exists())
        leftovers = list(self.share.glob(".kuft-*"))
        self.assertEqual(leftovers, [], "a temp file was left behind")

    def test_upload_of_missing_local_file(self):
        client = self.connected()
        with self.assertRaises(TransferError):
            client.upload(str(self.outbox / "not-here.txt"))

    def test_mkdir_and_delete(self):
        client = self.connected()
        self.assertEqual(client.request(Request("MKDIR", "/newdir")).code, 201)
        self.assertTrue((self.share / "newdir").is_dir())
        self.assertEqual(client.request(Request("MKDIR", "/newdir")).code, 409)
        self.assertEqual(client.request(Request("DELETE", "/newdir")).code, 204)

    def test_delete_non_empty_directory_is_409(self):
        client = self.connected()
        self.assertEqual(client.request(Request("DELETE", "/sub")).code, 409)

    def test_delete_share_root_is_403(self):
        client = self.connected()
        self.assertEqual(client.request(Request("DELETE", "/")).code, 403)

    def test_move_renames(self):
        client = self.connected()
        client.upload(str(self.outbox / "upload.txt"), "tomove.txt")
        resp = client.request(
            Request("MOVE", "/tomove.txt", {"destination": "/moved.txt"})
        )
        self.assertEqual(resp.code, 200)
        self.assertTrue((self.share / "moved.txt").exists())

    def test_move_without_destination_is_400(self):
        client = self.connected()
        self.assertEqual(client.request(Request("MOVE", "/readme.txt")).code, 400)

    def test_path_traversal_is_403(self):
        client = self.connected()
        for attack in ("../secrets", "/../secrets", "sub/../../secrets", "..\\secrets"):
            with self.subTest(attack=attack):
                self.assertEqual(client.request(Request("STAT", attack)).code, 403)

    def test_absolute_windows_path_is_contained(self):
        client = self.connected()
        resp = client.request(Request("STAT", "C:/Windows/win.ini"))
        self.assertIn(resp.code, (403, 404))

    def test_filename_with_spaces_roundtrips(self):
        client = self.connected()
        name = "a file with spaces.txt"
        client.upload(str(self.outbox / "upload.txt"), name)
        self.assertTrue((self.share / name).exists())
        path = client.download("/" + name)
        self.assertEqual(path.read_text(encoding="utf-8"), "client payload\n")

    def test_unicode_filename_roundtrips(self):
        client = self.connected()
        name = "รายงาน.txt"
        client.upload(str(self.outbox / "upload.txt"), name)
        self.assertTrue((self.share / name).exists())

    def test_oversize_upload_is_413(self):
        client = self.connected()
        big = Path(self.tmp.name) / "toobig.bin"
        big.write_bytes(b"x" * (self.harness.cfg.max_upload + 1024))
        with self.assertRaises(TransferError) as ctx:
            client.upload(str(big), "toobig.bin")
        self.assertIn("413", str(ctx.exception))

    def test_bad_range_is_416(self):
        client = self.connected()
        resp = client.request(Request("GET", "/readme.txt", {"range": "999999"}))
        self.assertEqual(resp.code, 416)

    def test_quit_closes_politely(self):
        client = self.make_client()
        client.connect(code=self.code)
        resp = client.request(Request("QUIT", "*"))
        self.assertEqual(resp.code, 200)
        self.assertEqual(resp.headers.get("connection"), "close")
        client.close()

    def test_zero_byte_file_roundtrips(self):
        client = self.connected()
        empty = self.outbox / "empty.dat"
        empty.write_bytes(b"")
        client.upload(str(empty), "empty.dat")
        path = client.download("/empty.dat", "empty-back.dat")
        self.assertEqual(path.stat().st_size, 0)


class ReadOnlyTests(E2EBase):
    read_only = True

    def test_reads_are_allowed(self):
        client = self.connected()
        self.assertEqual(client.request(Request("LIST", "/")).code, 200)

    def test_writes_are_403(self):
        client = self.connected()
        for method, target in (
            ("PUT", "/x.txt"),
            ("DELETE", "/readme.txt"),
            ("MKDIR", "/d"),
            ("MOVE", "/readme.txt"),
        ):
            with self.subTest(method=method):
                self.assertEqual(client.request(Request(method, target)).code, 403)

    def test_the_file_really_survives(self):
        self.assertTrue((self.share / "readme.txt").exists())


class RateLimitTests(E2EBase):
    rate_limit = 5

    def test_burst_gets_429(self):
        client = self.connected()
        codes = [client.request(Request("STAT", "/readme.txt")).code for _ in range(12)]
        self.assertIn(429, codes)
        self.assertEqual(codes[0], 200, "the first request should still succeed")


class CapacityTests(E2EBase):
    max_clients = 1

    def test_second_client_is_refused(self):
        first = self.connected()
        self.assertEqual(first.request(Request("LIST", "/")).code, 200)

        second = self.make_client()
        self.addCleanup(second.close)
        with self.assertRaises((TransferError, ConnectionError, OSError)):
            second.connect(code=self.code)


if __name__ == "__main__":
    unittest.main(verbosity=2)
