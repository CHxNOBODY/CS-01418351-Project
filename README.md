# KUFT — encrypted file transfer between two computers

### CS-01418351 · Computer Networks

Send a file from one machine to another over your own network, encrypted, from
a terminal. No cloud, no account, no USB stick. Two commands.

```
   sender                                    receiver
     |                                          |
     |<========== TCP + TLS 1.3 handshake ======|
     |------- HELLO * KUFT ------------------->|   capabilities + salt + nonce
     |<------ AUTH  (proof of pairing code) ---|   both sides prove the code
     |------- KUFT/2.0 200 OK (server proof) ->|
     |<------ GET report.pdf ------------------|
     |------- 200 OK + checksum + 8213 octets ->|   verified as it lands
```

---

## Quick start

**On the computer that has the files:**

```powershell
python kuft.py serve
```

Put whatever you want to send into the `share` folder next to `kuft.py`. The
server prints an address and a pairing code:

```
+----------------------------------------------------------------+
| KUFT/2.0 secure file share                                     |
|                                                                |
|   sharing    D:\Code\coursework\CS-01418351\share              |
|   listening  0.0.0.0:5150   TLS 1.3                            |
|                                                                |
|   On the other computer, run:                                  |
|     python kuft.py connect 192.168.1.114 --port 5150           |
|                                                                |
|   Pairing code   6D66-63UE-L7M6                                |
|   Fingerprint    OJET-5CS7-3W3E-MK7B-2YI4-IFFH                 |
+----------------------------------------------------------------+
```

**On the computer that wants them:**

```powershell
python kuft.py connect 192.168.1.114
```

Type the pairing code once. Then:

```text
kuft /> ls
kuft /> get big.bin
kuft /> put outbox/report.md
kuft /> quit
```

That is the whole tool. Everything below is detail.

### Before the first run

```powershell
python kuft.py doctor
```

It checks the Python version, that TLS 1.3 is available, and that the
`cryptography` package is installed — and tells you exactly what to do if
something is missing. Run it on **both** machines.

If you need the dependency:

```powershell
python -m pip install cryptography
```

> On this machine `python` resolves to an MSYS2 build with no pip. `kuft.py`
> notices, finds the python.org interpreter that does have `cryptography`, and
> hands off to it automatically — so `python kuft.py serve` works either way.
> `doctor` reports which interpreter it will use.

---

## How the security works

Encryption without knowing *who* you are talking to is worth very little, so
KUFT does two things.

**1. TLS 1.3 for the channel.** Nothing below 1.3 is accepted, so there is no
downgrade to negotiate and no legacy cipher to fall back to. The server makes
its own certificate on first run and keeps it in `~/.kuft/`.

**2. A pairing code that binds to that certificate.** The certificate is
self-signed — there is no certificate authority on a two-laptop network — so
a fingerprint alone proves nothing on its own. Instead:

* the server prints a 60-bit code, shown as `XXXX-XXXX-XXXX`;
* both ends stretch it with PBKDF2 (200,000 rounds) into a key;
* the client HMACs *the certificate fingerprint* plus two fresh nonces under
  that key, and the server checks it;
* the server returns a different HMAC over the same material, so the client
  knows the server holds the code too.

Binding the proof to the fingerprint is what defeats a machine-in-the-middle.
An attacker who terminates TLS has to present its own certificate, so the
proof it relays no longer matches, and both sides stop.

**After pairing, the client pins.** The fingerprint and derived key go into
`~/.kuft/known_hosts.json`, and later connections are silent — exactly like
SSH. If the fingerprint ever changes, the client **refuses to connect** and
tells you how to override deliberately. There is no "continue anyway" prompt,
because that prompt is how people get intercepted.

### What it does not protect against

Worth being honest about:

* **Anyone who can read `~/.kuft/known_hosts.json`** can impersonate that
  client. Same trust level as an SSH private key.
* **The pairing code is only as private as the way you shared it.** Read it
  off the screen, or say it out loud. Do not send it over the same network
  you are worried about.
* **No forward secrecy across a code change** for already-paired clients:
  rotating the code (`--new-code`) forces everyone to pair again, which is the
  intended way to revoke access.
* **The server trusts anyone with the code.** There are no per-user accounts.
  For a share between your own machines that is the right amount of ceremony;
  for a multi-user deployment it is not.

---

## Commands

```
python kuft.py                     a short tour
python kuft.py serve  [options]    share a directory
python kuft.py connect HOST [opts] open a session
python kuft.py doctor              check this machine is ready
python kuft.py id                  show this machine's code + fingerprint
python kuft.py hosts               servers already paired with
python kuft.py forget HOST         un-pin a server
```

### `serve`

| Option | Default | Meaning |
| --- | --- | --- |
| `--host` | `0.0.0.0` | Interface to bind. `0.0.0.0` accepts other machines. |
| `--port` | `5150` | TCP port. |
| `--share` | `share/` next to `kuft.py` | Directory to serve. A relative path is taken from the current directory. Nothing outside it is reachable. |
| `--read-only` | off | Refuse `PUT`, `DELETE`, `MKDIR`, `MOVE`. |
| `--max-clients` | `8` | Concurrent sessions before new ones get `503`. |
| `--rate-limit` | `0` (off) | Requests per 10 s per connection before `429`. |
| `--max-upload` | `8192` | Largest accepted upload, in MB. |
| `--new-code` | off | Rotate the pairing code; all clients must pair again. |
| `--verbose` | off | Log the detail line of every reply. |
| `--no-color` | off | Plain output, for capture. |

### `connect`

| Option | Default | Meaning |
| --- | --- | --- |
| `--port` | `5150` | Server port. |
| `--downloads` | `./downloads` | Where `get` saves files. |
| `--code CODE` | — | Supply the pairing code instead of being prompted. |
| `--get FILE` | — | Download one file and exit. |
| `--put FILE` | — | Upload one file and exit. |
| `--as NAME` | — | Name to use with `--get` / `--put`. |
| `--force` | off | Let `--put` overwrite. |
| `--ls [DIR]` | — | List a directory and exit. |
| `--no-color` | off | Plain output. |

One-shot mode is there for scripting:

```powershell
python kuft.py connect 192.168.1.114 --get big.bin
python kuft.py connect 192.168.1.114 --put report.pdf --force
```

### At the `kuft />` prompt

| Remote | | Local | |
| --- | --- | --- | --- |
| `ls [dir]` | list a directory | `lls [dir]` | list a local directory |
| `cd <dir>` | change remote directory | `lcd <dir>` | change local directory |
| `pwd` | show remote directory | `lpwd` | show local directory |
| `stat <file>` | size, time, checksum | `lrm <file>` | delete a local file |
| `get <f> [as]` | download, resumable | | |
| `put <f> [as]` | upload (`--force` to replace) | | |
| `mkdir <dir>` | create a directory | | |
| `rm <path>` | delete a file or empty directory **on the server** | | |
| `mv <f> <dir>` | move a file into a directory | | |
| `rn <f> <name>` | rename a file where it sits | | |
| `info` | TLS, cipher, fingerprint | `help` | command list |
| `quit` | close politely | | |

---

## What it guarantees about your files

* **Integrity, end to end.** Every transfer carries a SHA-256. Downloads are
  hashed as they land and again over the assembled file; a mismatch leaves the
  data as `.part` and reports `422` rather than handing you a bad file.
* **Atomic uploads.** The server writes to a temporary file and renames it into
  place only after the checksum matches, so a failed or tampered upload never
  replaces a good file.
* **Resumable downloads.** Interrupt a transfer and run the same `get` again;
  it continues from the `.part` file and still verifies the whole result.
* **A real jail.** Request targets are resolved and then checked against the
  share root, so `../`, absolute paths and symlinks pointing outside are all
  refused with `403`.
* **Any filename.** Targets are percent-encoded on the wire, so spaces and
  non-ASCII names survive — `Quarterly Report (final) ผลลัพธ์.txt` transfers
  intact.
* **Constant memory.** Bodies stream in 256 KB blocks. A 40 GB file uses the
  same memory as a 4 KB one.

---

## Testing

**By hand** — [`MANUAL-TESTS.md`](MANUAL-TESTS.md) is a step-by-step guide with
the exact commands to type, what to expect, and reference checksums. Build the
sample data first:

```powershell
python make_testdata.py
```

**Automatically:**

```powershell
python -m unittest discover -s tests -v
```

68 tests in three layers: the codec with no sockets; the pairing crypto; and a
real TLS server on an ephemeral port driven by the real client — including
wrong codes, changed fingerprints, path traversal, checksum failure, rate
limits and capacity limits.

---

## Two computers, practically

Both machines need Python 3.10+ and `cryptography`. Then:

1. `python kuft.py serve` on the sender. Note the address and code it prints.
2. Allow it through the firewall when Windows asks — **private networks**.
3. `Test-NetConnection <address> -Port 5150` on the receiver should say
   `TcpTestSucceeded : True`.
4. `python kuft.py connect <address>`, type the code, `get` what you need.

If step 3 fails it is the network, not KUFT. Many public and university Wi-Fi
networks isolate clients from each other, which blocks this entirely; a phone
hotspot with both machines on it is the usual way around that.

---

## Layout

```text
kuft.py                  the only entry point
make_testdata.py         builds share/ and outbox/ sample files
requirements.txt         cryptography

src/kuft/
    bootstrap.py         finds an interpreter that can run KUFT
    crypto.py            keys, certificates, pairing codes, known hosts
    protocol.py          the wire format: encode, decode, stream, status codes
    term.py              colour, progress bars, tables
    server.py            TLS server, session state machine, handlers
    client.py            pairing, pinning, the interactive shell

share/                   what the server offers
outbox/                  what the client uploads
downloads/               where get saves files
~/.kuft/                 keys, pairing code, known hosts  (not in the project)

docs/KUFT-2.0-spec.md    the protocol specification
MANUAL-TESTS.md          the test guide you type through
tests/test_kuft.py       the automated suite
```

`protocol.py` is imported by both sides, so client and server cannot drift
apart on the format.

---

## Where your keys live

Everything private is under `~/.kuft/` — on Windows,
`C:\Users\<you>\.kuft\` — never inside the project folder:

| File | What it is |
| --- | --- |
| `server_key.pem` | This machine's private key. Never leaves the machine. |
| `server_cert.pem` | The self-signed certificate clients pin. |
| `server.json` | The pairing code and its salt. |
| `known_hosts.json` | Servers this machine has paired with. |

Delete the directory to reset this machine's identity completely; every client
that had paired with it will then correctly refuse to connect until you pair
again.
