"""Identity, certificates and pairing for KUFT/2.0.

Three jobs live here:

*   **Server identity** -- a long-lived ECDSA P-256 key and the self-signed
    certificate that wraps it, created on first run and reused afterwards.
*   **Pairing** -- a 60-bit shared secret, shown to the operator as
    ``XXXX-XXXX-XXXX``, that proves each end is talking to the other and not
    to somebody in the middle.
*   **Known hosts** -- the client's memory of which certificate belongs to
    which server, so the code only has to be typed once.

The pairing exchange is a channel-bound challenge/response.  Both sides derive
a key from the code with PBKDF2, then HMAC over *the certificate fingerprint*
together with two nonces.  Binding the proof to the fingerprint is what stops a
relay attack: an attacker who terminates TLS presents a different certificate,
so the proof it forwards no longer verifies.
"""

from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import hmac
import ipaddress
import json
import os
import secrets
import socket
import stat
from dataclasses import dataclass
from pathlib import Path

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
except ImportError as exc:  # pragma: no cover - the bootstrap handles this
    raise SystemExit(
        "KUFT needs the 'cryptography' package.\n"
        "Run:  python kuft.py doctor\n"
        f"({exc})"
    ) from exc

# ---------------------------------------------------------------- parameters

#: RFC 4648 base32.  It has no 0/1/8/9, so a printed code cannot be misread
#: between O and 0 or between I and 1 when somebody reads it aloud.
CODE_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

CODE_CHARS = 12  # 12 * 5 bits = 60 bits of entropy
PBKDF2_ROUNDS = 200_000
KEY_BYTES = 32
NONCE_BYTES = 32
SALT_BYTES = 16
CERT_YEARS = 10

_CLIENT_LABEL = b"KUFT/2.0 client-proof"
_SERVER_LABEL = b"KUFT/2.0 server-proof"

#: Characters people type when they meant a base32 character.
_CONFUSABLES = str.maketrans({"0": "O", "1": "I", "8": "B", "9": "G"})


def identity_dir() -> Path:
    """Where this machine keeps its key, pairing code and known hosts."""
    override = os.environ.get("KUFT_HOME")
    base = Path(override) if override else Path.home() / ".kuft"
    base.mkdir(parents=True, exist_ok=True)
    _lock_down(base)
    return base


def _lock_down(path: Path) -> None:
    """Best-effort 0700/0600.  A no-op on filesystems that do not care."""
    try:
        mode = stat.S_IRWXU if path.is_dir() else stat.S_IRUSR | stat.S_IWUSR
        path.chmod(mode)
    except OSError:
        pass


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def unb64(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"), validate=True)


def new_nonce() -> bytes:
    return secrets.token_bytes(NONCE_BYTES)


# -------------------------------------------------------------- pairing code


def generate_code() -> str:
    """A fresh 60-bit pairing code, already grouped for reading."""
    raw = "".join(secrets.choice(CODE_ALPHABET) for _ in range(CODE_CHARS))
    return format_code(raw)


def format_code(raw: str) -> str:
    """``ABCDEFGHIJKL`` -> ``ABCD-EFGH-IJKL``."""
    raw = normalize_code(raw)
    return "-".join(raw[i : i + 4] for i in range(0, len(raw), 4))


def normalize_code(text: str) -> str:
    """Strip formatting and repair the characters people commonly mistype.

    Raises ``ValueError`` if what is left cannot be a pairing code.
    """
    cleaned = "".join(ch for ch in text.strip().upper() if ch.isalnum())
    cleaned = cleaned.translate(_CONFUSABLES)
    if len(cleaned) != CODE_CHARS:
        raise ValueError(
            f"a pairing code is {CODE_CHARS} characters, you gave {len(cleaned)}"
        )
    bad = sorted(set(cleaned) - set(CODE_ALPHABET))
    if bad:
        raise ValueError("not a pairing-code character: " + " ".join(bad))
    return cleaned


def derive_auth_key(code: str, salt: bytes) -> bytes:
    """Stretch the pairing code into a 32-byte authentication key.

    PBKDF2 is deliberate.  It makes a captured proof expensive to attack
    offline; 60 bits behind 200k rounds is far past what anyone will grind
    through for a file share.
    """
    normalized = normalize_code(code).encode("ascii")
    return hashlib.pbkdf2_hmac("sha256", normalized, salt, PBKDF2_ROUNDS, KEY_BYTES)


def _proof(
    label: bytes, key: bytes, fingerprint: bytes, c_nonce: bytes, s_nonce: bytes
) -> bytes:
    """Length-prefixed HMAC, so no two different inputs can collide."""
    mac = hmac.new(key, digestmod=hashlib.sha256)
    for part in (label, fingerprint, c_nonce, s_nonce):
        mac.update(len(part).to_bytes(4, "big"))
        mac.update(part)
    return mac.digest()


def client_proof(key: bytes, fingerprint: bytes, c_nonce: bytes, s_nonce: bytes) -> bytes:
    """What the client sends to prove it knows the code."""
    return _proof(_CLIENT_LABEL, key, fingerprint, c_nonce, s_nonce)


def server_proof(key: bytes, fingerprint: bytes, c_nonce: bytes, s_nonce: bytes) -> bytes:
    """What the server sends back, so the client knows the server is genuine."""
    return _proof(_SERVER_LABEL, key, fingerprint, c_nonce, s_nonce)


# --------------------------------------------------------------- fingerprint


def cert_fingerprint(der: bytes) -> bytes:
    """SHA-256 over the DER certificate -- the value clients pin."""
    return hashlib.sha256(der).digest()


def format_fingerprint(digest: bytes) -> str:
    """Render a fingerprint the way people compare it: grouped base32."""
    text = base64.b32encode(digest).decode("ascii").rstrip("=")
    return "-".join(text[i : i + 4] for i in range(0, 24, 4))


# ----------------------------------------------------------- server identity


@dataclass
class ServerIdentity:
    """This machine's key, certificate and pairing secret."""

    key_path: Path
    cert_path: Path
    config_path: Path
    code: str
    salt: bytes
    fingerprint: bytes
    auth_key: bytes

    @property
    def pretty_fingerprint(self) -> str:
        return format_fingerprint(self.fingerprint)

    @classmethod
    def load_or_create(
        cls, home: Path | None = None, *, rotate_code: bool = False
    ) -> ServerIdentity:
        home = home or identity_dir()
        key_path = home / "server_key.pem"
        cert_path = home / "server_cert.pem"
        config_path = home / "server.json"

        if not (key_path.exists() and cert_path.exists()):
            _create_keypair(key_path, cert_path)

        config: dict = {}
        if config_path.exists():
            try:
                config = json.loads(config_path.read_text("utf-8"))
            except (OSError, json.JSONDecodeError):
                config = {}

        code = config.get("pairing_code")
        salt_text = config.get("salt")
        if rotate_code or not code or not salt_text:
            code = generate_code()
            salt = secrets.token_bytes(SALT_BYTES)
            config_path.write_text(
                json.dumps({"pairing_code": code, "salt": b64(salt)}, indent=2),
                encoding="utf-8",
            )
            _lock_down(config_path)
        else:
            salt = unb64(salt_text)

        der = x509.load_pem_x509_certificate(cert_path.read_bytes()).public_bytes(
            serialization.Encoding.DER
        )
        return cls(
            key_path=key_path,
            cert_path=cert_path,
            config_path=config_path,
            code=format_code(code),
            salt=salt,
            fingerprint=cert_fingerprint(der),
            auth_key=derive_auth_key(code, salt),
        )


def _local_addresses() -> list[str]:
    """Every address worth listing in the certificate's SAN extension."""
    found = {"127.0.0.1", "::1"}
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            found.add(info[4][0].split("%")[0])
    except OSError:
        pass
    return sorted(found)


def _create_keypair(key_path: Path, cert_path: Path) -> None:
    """Mint a P-256 key and a long-lived self-signed certificate.

    Self-signed is the right shape here: there is no CA to appeal to on a
    two-laptop network, so trust comes from the pinned fingerprint instead.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    hostname = socket.gethostname()
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, f"kuft-{hostname}"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "KUFT/2.0"),
        ]
    )

    sans: list[x509.GeneralName] = [x509.DNSName(hostname), x509.DNSName("localhost")]
    for addr in _local_addresses():
        try:
            sans.append(x509.IPAddress(ipaddress.ip_address(addr)))
        except ValueError:
            continue

    now = _dt.datetime.now(_dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _dt.timedelta(minutes=5))
        .not_valid_after(now + _dt.timedelta(days=365 * CERT_YEARS))
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                key_agreement=True,
                content_commitment=False,
                data_encipherment=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )

    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    _lock_down(key_path)
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


# --------------------------------------------------------------- known hosts


@dataclass
class HostRecord:
    fingerprint: bytes
    auth_key: bytes


class KnownHosts:
    """The client's memory of servers it has already paired with.

    Storing the derived key -- not the code -- is what lets the second
    connection skip the prompt.  The file is chmod 600; anyone who can read it
    can impersonate this client, which is the same trust level as an SSH
    private key.
    """

    def __init__(self, path: Path | None = None):
        self.path = path or (identity_dir() / "known_hosts.json")
        self._entries: dict[str, HostRecord] = {}
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            raw = json.loads(self.path.read_text("utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        for host, item in raw.items():
            try:
                self._entries[host] = HostRecord(
                    fingerprint=unb64(item["fingerprint"]),
                    auth_key=unb64(item["auth_key"]),
                )
            except (KeyError, TypeError, ValueError):
                continue

    def _save(self) -> None:
        payload = {
            host: {"fingerprint": b64(rec.fingerprint), "auth_key": b64(rec.auth_key)}
            for host, rec in self._entries.items()
        }
        self.path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        _lock_down(self.path)

    @staticmethod
    def key_for(host: str, port: int) -> str:
        return f"{host}:{port}"

    def get(self, host: str, port: int) -> HostRecord | None:
        return self._entries.get(self.key_for(host, port))

    def remember(
        self, host: str, port: int, fingerprint: bytes, auth_key: bytes
    ) -> None:
        self._entries[self.key_for(host, port)] = HostRecord(fingerprint, auth_key)
        self._save()

    def forget(self, host: str, port: int) -> bool:
        removed = self._entries.pop(self.key_for(host, port), None) is not None
        if removed:
            self._save()
        return removed

    def items(self) -> list[tuple[str, HostRecord]]:
        return sorted(self._entries.items())
