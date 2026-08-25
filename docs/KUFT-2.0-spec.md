# KUFT/2.0 — Kasetsart University File Transfer, version 2

**Status:** implemented in `src/kuft/`
**Course:** CS-01418351 Computer Networks
**Supersedes:** KUFT/1.0, which ran in the clear and authenticated with a
username and password.

---

## 1. Purpose

KUFT/2.0 moves files between two computers that are on the same network and
belong to the same person, with confidentiality, integrity and mutual
authentication, and without depending on any third party — no certificate
authority, no directory service, no cloud relay.

It is deliberately small. It does not synchronise, it does not version, and it
does not manage users. It lists a directory, reports metadata, and moves bytes
in either direction, verifiably.

### 1.1 What version 2 changes and why

| KUFT/1.0 | KUFT/2.0 | Reason |
| --- | --- | --- |
| Plaintext TCP | TLS 1.3 required | Credentials and file contents were readable by anyone on the path. |
| Username + password | 60-bit pairing code | A password proves the client to the server but not the server to the client. |
| No server authentication | Certificate pinning bound into the auth proof | Without it, encryption only protects you from a passive listener. |
| Whole body buffered | Streamed in 256 KB blocks | 1.0 could not move a file larger than memory. |
| Bare target in request line | Percent-encoded target | `GET my file.txt KUFT/1.0` parsed as four tokens and failed. |
| Body checksum only | Checksum plus atomic rename, plus resume | A failed transfer could replace a good file with a truncated one. |

---

## 2. Characteristics

| Property | Choice |
| --- | --- |
| Transport | TCP, default port 5150 |
| Security | TLS 1.3 minimum, no downgrade permitted |
| Framing | Text head, blank line, counted binary body |
| Head charset | US-ASCII in the start line; UTF-8 in header values |
| Session | Stateful: greeted → authenticated → operating |
| Concurrency | One connection per session; server is threaded |
| Direction | Client always initiates; the server never sends unsolicited data |

### 2.1 Why TCP and not UDP

The protocol moves files, and a file is only useful if every octet arrives, in
order, exactly once. TCP already provides that: ordered delivery,
retransmission of loss, flow control so a fast sender cannot drown a slow
receiver, and congestion control so a transfer shares the link fairly.

Building the same guarantees on UDP would mean re-implementing sequence
numbers, acknowledgements, retransmission timers, windowing and congestion
control inside the application — which is to say, re-implementing TCP, worse.

The decisive point for version 2 is TLS. TLS 1.3 over TCP is a mature, widely
audited stack available in the Python standard library. The UDP equivalent,
DTLS, is not exposed by Python's `ssl` module at all. Choosing UDP would have
meant either writing our own record layer and key exchange — the classic way to
get security wrong — or shipping without encryption.

UDP would be the right call for a protocol where a late datagram is worthless:
live audio, video, telemetry. For file transfer, where a late octet is still
exactly as valuable as a punctual one, its advantages do not apply.

---

## 3. Message format

```
message   = head CRLF [ body ]
head      = start-line CRLF *( header CRLF )
header    = field-name ":" OWS field-value
```

* `start-line` is US-ASCII.
* Header names are case-insensitive and normalised to lower case on receipt.
* Header values are UTF-8 and must not contain CR or LF. An implementation
  must refuse to *encode* a value containing either, which is what closes the
  header-injection hole.
* The head ends at the first empty line.
* A body is present if and only if `content-length` is present and non-zero.
  The body is exactly that many octets and is otherwise uninterpreted, so it
  may contain CRLF, NUL, or any other byte with no escaping.

### 3.1 Request line

```
request-line = method SP target SP "KUFT/2.0"
```

`target` is **percent-encoded**: every octet outside `A-Z a-z 0-9 / * - . _ ~`
is written as `%XX` over its UTF-8 encoding. This guarantees the request line
is exactly three space-separated tokens regardless of the filename, and lets
any Unicode name transfer unchanged.

```
GET /Quarterly%20Report%20(final).pdf KUFT/2.0
PUT /%E0%B8%A3%E0%B8%B2%E0%B8%A2%E0%B8%87%E0%B8%B2%E0%B8%99.txt KUFT/2.0
```

### 3.2 Status line

```
status-line = "KUFT/2.0" SP status-code SP reason-phrase
```

### 3.3 Limits

| Limit | Value | Enforced by |
| --- | --- | --- |
| Control line | 8192 octets | `400` |
| Headers per message | 64 | `400` |
| Control body (listings, proofs) | 4 MiB | `413` |
| Upload body | server's `--max-upload`, default 8 GiB | `413` |
| Transfer block size | 256 KiB | — |

---

## 4. Methods

| Method | Target | Body | Purpose |
| --- | --- | --- | --- |
| `HELLO` | `*` | — | Negotiate; obtain salt and server nonce. |
| `AUTH` | `*` | — | Prove knowledge of the pairing code. |
| `LIST` | directory | — | Directory listing. |
| `STAT` | file | — | Size, mtime, checksum. No transfer. |
| `GET` | file | — | Download; `range` requests a suffix. |
| `PUT` | file | payload | Upload. |
| `DELETE` | path | — | Remove a file or empty directory. |
| `MKDIR` | directory | — | Create a directory. |
| `MOVE` | path | — | Rename; `destination` header gives the new path. |
| `QUIT` | `*` | — | Close politely. |

`HELLO` and `AUTH` are the only methods permitted before authentication;
everything else returns `401` until `AUTH` succeeds.

---

## 5. Status codes

### Success

| Code | Phrase | When |
| --- | --- | --- |
| 200 | OK | Request succeeded; a `PUT` replaced an existing file. |
| 201 | CREATED | `PUT` or `MKDIR` created something new. |
| 204 | NO CONTENT | `DELETE` succeeded. |
| 206 | PARTIAL CONTENT | `GET` with a `range`; body is a suffix. |

### Client errors

| Code | Phrase | When |
| --- | --- | --- |
| 400 | BAD REQUEST | Unparseable framing. The connection is closed after. |
| 401 | UNAUTHORIZED | Not authenticated, or the pairing proof did not verify. |
| 403 | FORBIDDEN | Path escapes the share, server is read-only, or the target is the share root. |
| 404 | NOT FOUND | No such file or directory. |
| 405 | METHOD NOT ALLOWED | Unknown method. |
| 409 | CONFLICT | Target exists and no overwrite was requested; directory not empty. |
| 413 | PAYLOAD TOO LARGE | Body exceeds the configured limit. |
| 416 | RANGE NOT SATISFIABLE | `range` outside the file, or a resume offset the server cannot match. |
| 422 | CHECKSUM MISMATCH | Received data does not match the declared checksum. |
| 429 | TOO MANY REQUESTS | Rate limit exceeded. `retry-after` gives seconds. |

### Server errors

| Code | Phrase | When |
| --- | --- | --- |
| 500 | INTERNAL ERROR | Unexpected failure while handling a valid request. |
| 503 | SERVICE UNAVAILABLE | At `--max-clients`; sent before the session starts. |
| 505 | VERSION NOT SUPPORTED | Request declared a version other than `KUFT/2.0`. |

Every response carries a `detail` header with a human-readable explanation.
Both programs print the code, the phrase and the detail for every exchange.

---

## 6. The pairing exchange

This is the part that makes encryption meaningful, so it is specified exactly.

### 6.1 Values

| Symbol | Definition |
| --- | --- |
| `code` | 12 characters from RFC 4648 base32 — 60 bits. Case-insensitive; dashes ignored; `0 1 8 9` are read as `O I B G`. |
| `salt` | 16 random octets, generated once per server and stored. |
| `K` | `PBKDF2-HMAC-SHA256(code, salt, 200000, 32)` |
| `FP` | `SHA-256(DER(server certificate))` — 32 octets. |
| `Nc`, `Ns` | 32 random octets, fresh for every connection. |

### 6.2 Proof construction

With `L(x)` the 4-octet big-endian length of `x`:

```
proof(label) = HMAC-SHA256( K,
                 L(label) || label ||
                 L(FP)    || FP    ||
                 L(Nc)    || Nc    ||
                 L(Ns)    || Ns    )

client proof: label = "KUFT/2.0 client-proof"
server proof: label = "KUFT/2.0 server-proof"
```

Length prefixes make the encoding injective, so no two different inputs can
produce the same byte string to be MACed. Distinct labels stop a client proof
being replayed as a server proof.

### 6.3 Exchange

```
C -> S   HELLO * KUFT/2.0

S -> C   KUFT/2.0 200 OK
         salt:  <base64>
         nonce: <base64 Ns>
         auth:  pairing-code

C -> S   AUTH * KUFT/2.0
         nonce: <base64 Nc>
         proof: <base64 proof("KUFT/2.0 client-proof")>

S -> C   KUFT/2.0 200 OK
         proof: <base64 proof("KUFT/2.0 server-proof")>
```

Both comparisons use a constant-time equality test. A failed client proof
returns `401` after a one-second delay and leaves the session unauthenticated;
the connection is not closed, so an operator can retype the code.

### 6.4 Why the fingerprint is inside the MAC

Suppose an attacker sits between the two machines, terminating TLS on both
sides with a certificate of its own, fingerprint `FP'`.

The client computes its proof over `FP'`, because that is the certificate it
was shown. The attacker forwards that proof to the real server, which computes
its expectation over `FP` — its own fingerprint. `FP ≠ FP'`, so the MACs
differ and the server returns `401`.

The attacker cannot repair this without `K`, and cannot derive `K` without the
code, which never crosses the network in any form. A captured proof is subject
only to an offline attack against 60 bits behind 200,000 PBKDF2 rounds.

### 6.5 Pinning

On the first successful exchange the client stores `FP` and `K` against
`host:port`. Later connections skip the code entirely and reuse `K`.

If a stored `FP` does not match what is presented, the client **aborts**. It
does not prompt. A changed fingerprint is either a rebuilt server — which the
operator can confirm out of band and clear with `forget` — or an interception,
and a dialog box is how people click through the second case.

---

## 7. Transfer semantics

### 7.1 Download

`GET` replies with `size`, `checksum` (over the transmitted window),
`whole-checksum` (over the entire file) and the body.

The client hashes as it writes and compares against `checksum`; on success it
hashes the assembled file and compares against `whole-checksum`. Both must
pass before the `.part` file is renamed to its final name. A failure leaves the
`.part` in place, which is what makes the next attempt resumable.

With a `range: N` header the server seeks to `N` and replies `206`, with
`checksum` covering only octets `N` onwards.

### 7.2 Upload

`PUT` carries `checksum` and, optionally, `overwrite: true`.

The server writes the body to a temporary file in the destination directory,
hashes it, compares, and only then `rename`s it into place. The rename is
atomic within a filesystem, so an interrupted or corrupted upload can never
leave a partially written file under the real name — the previous version
survives untouched.

If the target exists and `overwrite` is absent, the server replies `409` before
writing anything. The client also issues a `STAT` first and refuses locally,
so a large upload is not sent only to be rejected.

A `range: N` header on `PUT` appends from offset `N`, provided the server's
current size is exactly `N`; otherwise `416`.

### 7.3 Path resolution

Every target is resolved against the share root and then checked to be the root
or one of its descendants. Resolution collapses `..` and follows symlinks
*before* the check, so a symlink pointing outside the share is refused just as
a literal `../` is. Failures are `403`, not `404`, and the reply never
discloses whether the outside path exists.

---

## 8. Session state machine

```
                 TLS 1.3 handshake
                        |
                        v
                  [ connected ]
                        |  HELLO
                        v
                   [ greeted ]
                        |  AUTH with a valid proof
                        v
                 [ authenticated ] <--+
                        |             | LIST STAT GET PUT
                        |  QUIT       | DELETE MKDIR MOVE
                        v             |
                    [ closed ]  ------+
```

* Any method other than `HELLO` or `AUTH` in `connected` or `greeted` → `401`.
* `AUTH` before `HELLO` → `400`, since there is no `Ns` to bind to.
* A `400` framing error closes the connection: once the stream is out of sync
  there is no way to find the next message boundary.
* `QUIT` is answered `200` with `connection: close`.

---

## 9. Security considerations

**In scope.** Passive eavesdropping and active interception on the local
network; tampering with file contents in flight; path traversal; unauthenticated
access; resource exhaustion by request flooding or connection count.

**Out of scope, stated plainly.**

* The pairing code is a shared secret with no per-user identity. Anyone holding
  it has the same access as anyone else holding it.
* `known_hosts.json` contains the derived key `K`. Read access to that file is
  equivalent to holding the code for that server.
* Traffic analysis is not addressed: an observer learns the size and timing of
  every transfer, though not the names or contents.
* There is no revocation short of rotating the code, which revokes every
  client at once.
* The server executes as the invoking user with that user's file permissions.
  The share root is the only boundary; run it as an unprivileged account.

---

## 10. Conformance

An implementation conforms if it:

1. requires TLS 1.3 and refuses to proceed below it;
2. rejects any request whose version token is not `KUFT/2.0` with `505`;
3. percent-encodes and decodes targets as in §3.1;
4. implements the pairing exchange of §6 exactly, including length prefixes,
   labels and constant-time comparison;
5. resolves paths as in §7.3 and answers `403` on escape;
6. verifies checksums before making an uploaded file visible under its final
   name;
7. emits `content-length` on every message carrying a body, and no body when
   it is absent or zero;
8. returns the codes of §5 for the conditions listed there.

`tests/test_kuft.py` asserts every one of these, so the suite is the
executable form of this section.
