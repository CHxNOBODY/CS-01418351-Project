"""The KUFT/2.0 wire format.

A message is a text head followed by an optional binary body::

    GET report.pdf KUFT/2.0\\r\\n
    range: 0\\r\\n
    \\r\\n

    KUFT/2.0 200 OK\\r\\n
    content-length: 8213\\r\\n
    checksum: sha256=1f3a...\\r\\n
    \\r\\n
    <8213 octets>

Two rules make that unambiguous and keep the parser small:

*   the head is US-ASCII and ends at the first blank line, so a body may
    contain CRLF, NUL, or anything else without escaping;
*   ``content-length`` is mandatory whenever a body follows, so the receiver
    always knows exactly how many octets to read and never has to guess where
    a message ends.

Bodies are *streamed*.  Nothing here loads a whole file into memory, which is
what lets the same code move a 6 KB text file and a 6 GB disk image.

This module is imported by both the client and the server, so the two cannot
drift apart on the format.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import BinaryIO, Callable, Iterable
from urllib.parse import quote, unquote

VERSION = "KUFT/2.0"
CRLF = b"\r\n"

#: Guard rails against a hostile or broken peer.
MAX_LINE = 8 * 1024
MAX_HEADERS = 64
MAX_CONTROL_BODY = 4 * 1024 * 1024  # listings and errors, not file payloads
CHUNK = 256 * 1024

METHODS = (
    "HELLO",
    "AUTH",
    "LIST",
    "STAT",
    "GET",
    "PUT",
    "DELETE",
    "MKDIR",
    "MOVE",
    "QUIT",
)

STATUS_PHRASES = {
    200: "OK",
    201: "CREATED",
    204: "NO CONTENT",
    206: "PARTIAL CONTENT",
    400: "BAD REQUEST",
    401: "UNAUTHORIZED",
    403: "FORBIDDEN",
    404: "NOT FOUND",
    405: "METHOD NOT ALLOWED",
    409: "CONFLICT",
    413: "PAYLOAD TOO LARGE",
    416: "RANGE NOT SATISFIABLE",
    422: "CHECKSUM MISMATCH",
    429: "TOO MANY REQUESTS",
    500: "INTERNAL ERROR",
    503: "SERVICE UNAVAILABLE",
    505: "VERSION NOT SUPPORTED",
}


def phrase(code: int) -> str:
    return STATUS_PHRASES.get(code, "UNKNOWN")


class ProtocolError(Exception):
    """A message that cannot be parsed.  Carries the status code to reply."""

    def __init__(self, detail: str, code: int = 400):
        super().__init__(detail)
        self.detail = detail
        self.code = code


# ------------------------------------------------------------------ messages


#: Characters left alone when a target goes on the wire.  Everything else --
#: spaces, non-ASCII, control bytes -- is percent-encoded, so the request line
#: is always exactly three space-separated tokens no matter what a file is
#: called.  "Quarterly Report (final).pdf" would otherwise parse as five.
TARGET_SAFE = "/*-._~"


def encode_target(target: str) -> str:
    return quote(target, safe=TARGET_SAFE, encoding="utf-8")


def decode_target(raw: str) -> str:
    return unquote(raw, encoding="utf-8", errors="replace")


@dataclass
class Request:
    method: str
    target: str
    headers: dict[str, str] = field(default_factory=dict)

    def head_bytes(self) -> bytes:
        line = f"{self.method} {encode_target(self.target)} {VERSION}"
        return _encode_head(line, self.headers)


@dataclass
class Response:
    code: int
    headers: dict[str, str] = field(default_factory=dict)

    @property
    def phrase(self) -> str:
        return phrase(self.code)

    @property
    def ok(self) -> bool:
        return 200 <= self.code < 300

    @property
    def detail(self) -> str:
        return self.headers.get("detail", self.phrase)

    def head_bytes(self) -> bytes:
        return _encode_head(f"{VERSION} {self.code} {self.phrase}", self.headers)


def _encode_head(start_line: str, headers: dict[str, str]) -> bytes:
    out = bytearray(start_line.encode("ascii") + CRLF)
    for name, value in headers.items():
        text = str(value)
        if "\r" in text or "\n" in text:
            raise ValueError(f"header {name!r} contains a line break")
        out += f"{name}: {text}".encode("utf-8") + CRLF
    out += CRLF
    return bytes(out)


# ------------------------------------------------------------------- reading


class Reader:
    """Buffered reads over a socket file object, with the protocol's limits."""

    def __init__(self, stream: BinaryIO):
        self.stream = stream

    def read_line(self) -> bytes:
        line = self.stream.readline(MAX_LINE + 1)
        if not line:
            raise ConnectionError("peer closed the connection")
        if len(line) > MAX_LINE:
            raise ProtocolError(f"control line longer than {MAX_LINE} octets", 400)
        if not line.endswith(CRLF):
            raise ProtocolError("control line must end with CRLF", 400)
        return line[:-2]

    def read_head(self) -> tuple[str, dict[str, str]]:
        start_line = self.read_line().decode("ascii", "replace")
        if not start_line:
            raise ProtocolError("empty start line", 400)

        headers: dict[str, str] = {}
        while True:
            raw = self.read_line()
            if not raw:
                break
            if len(headers) >= MAX_HEADERS:
                raise ProtocolError(f"more than {MAX_HEADERS} headers", 400)
            if b":" not in raw:
                raise ProtocolError(f"malformed header line: {raw[:60]!r}", 400)
            name, _, value = raw.partition(b":")
            key = name.decode("utf-8", "replace").strip().lower()
            if not key:
                raise ProtocolError("header with an empty name", 400)
            headers[key] = value.decode("utf-8", "replace").strip()
        return start_line, headers

    def read_exactly(self, count: int) -> bytes:
        buf = bytearray()
        while len(buf) < count:
            block = self.stream.read(min(CHUNK, count - len(buf)))
            if not block:
                raise ProtocolError(
                    f"body truncated: wanted {count}, got {len(buf)}", 400
                )
            buf += block
        return bytes(buf)

    def drain_body(self, headers: dict[str, str]) -> bytes:
        """Read a control-sized body straight into memory."""
        length = body_length(headers)
        if length == 0:
            return b""
        if length > MAX_CONTROL_BODY:
            raise ProtocolError("control body too large", 413)
        return self.read_exactly(length)

    def pipe_body(
        self,
        headers: dict[str, str],
        sink: BinaryIO,
        *,
        on_progress: Callable[[int], None] | None = None,
    ) -> tuple[int, str]:
        """Stream ``content-length`` octets into ``sink``, hashing on the way.

        Returns the octet count and the SHA-256 of what was written, so the
        caller can compare it against the sender's ``checksum`` header without
        a second pass over the data.
        """
        remaining = body_length(headers)
        digest = hashlib.sha256()
        written = 0
        while remaining > 0:
            block = self.stream.read(min(CHUNK, remaining))
            if not block:
                raise ProtocolError(
                    f"body truncated: {remaining} octets missing", 400
                )
            sink.write(block)
            digest.update(block)
            written += len(block)
            remaining -= len(block)
            if on_progress:
                on_progress(written)
        return written, "sha256=" + digest.hexdigest()

    def read_request(self) -> Request:
        start_line, headers = self.read_head()
        parts = start_line.split(" ")
        if len(parts) != 3:
            raise ProtocolError(f"malformed request line: {start_line!r}", 400)
        method, raw_target, version = parts
        if version != VERSION:
            raise ProtocolError(f"this server speaks {VERSION}, not {version!r}", 505)
        if method not in METHODS:
            raise ProtocolError(f"unknown method {method!r}", 405)
        if not raw_target:
            raise ProtocolError("empty request target", 400)
        return Request(method=method, target=decode_target(raw_target), headers=headers)

    def read_response(self) -> Response:
        start_line, headers = self.read_head()
        parts = start_line.split(" ", 2)
        if len(parts) < 2 or parts[0] != VERSION:
            raise ProtocolError(f"malformed status line: {start_line!r}", 400)
        try:
            code = int(parts[1])
        except ValueError:
            raise ProtocolError(f"non-numeric status code: {parts[1]!r}", 400) from None
        return Response(code=code, headers=headers)


def body_length(headers: dict[str, str]) -> int:
    raw = headers.get("content-length")
    if raw is None:
        return 0
    try:
        length = int(raw)
    except ValueError:
        raise ProtocolError(f"content-length is not a number: {raw!r}", 400) from None
    if length < 0:
        raise ProtocolError("content-length is negative", 400)
    return length


# ------------------------------------------------------------------- writing


class Writer:
    """Writes heads and streams bodies, never buffering a whole payload."""

    def __init__(self, stream: BinaryIO):
        self.stream = stream

    def send_head(self, message: Request | Response) -> None:
        self.stream.write(message.head_bytes())
        self.stream.flush()

    def send_bytes(self, message: Request | Response, body: bytes) -> None:
        """Send a small in-memory body -- a listing, an error detail, a proof."""
        message.headers["content-length"] = str(len(body))
        self.stream.write(message.head_bytes())
        if body:
            self.stream.write(body)
        self.stream.flush()

    def send_stream(
        self,
        message: Request | Response,
        source: BinaryIO,
        length: int,
        *,
        on_progress: Callable[[int], None] | None = None,
    ) -> None:
        """Send ``length`` octets read from ``source`` in fixed-size blocks.

        The head must already carry the checksum, which means the sender hashes
        the file before the transfer starts.  That is the price of letting the
        receiver verify integrity as the bytes land, rather than after.
        """
        message.headers["content-length"] = str(length)
        self.stream.write(message.head_bytes())
        sent = 0
        while sent < length:
            block = source.read(min(CHUNK, length - sent))
            if not block:
                raise ProtocolError(
                    f"source ran dry {length - sent} octets early", 500
                )
            self.stream.write(block)
            sent += len(block)
            if on_progress:
                on_progress(sent)
        self.stream.flush()


# --------------------------------------------------------------- convenience


def checksum_file(path, *, offset: int = 0, length: int | None = None) -> str:
    """SHA-256 over a file, or over one window of it."""
    digest = hashlib.sha256()
    remaining = length
    with open(path, "rb") as handle:
        if offset:
            handle.seek(offset)
        while remaining is None or remaining > 0:
            want = CHUNK if remaining is None else min(CHUNK, remaining)
            block = handle.read(want)
            if not block:
                break
            digest.update(block)
            if remaining is not None:
                remaining -= len(block)
    return "sha256=" + digest.hexdigest()


def checksum_bytes(data: bytes) -> str:
    return "sha256=" + hashlib.sha256(data).hexdigest()


def error_response(code: int, detail: str, **extra: str) -> Response:
    headers = {"detail": detail}
    headers.update({k.replace("_", "-"): v for k, v in extra.items()})
    return Response(code=code, headers=headers)


def join_lines(rows: Iterable[str]) -> bytes:
    return ("\n".join(rows) + "\n").encode("utf-8")
