# Manual test guide

Everything here is meant to be **typed by you**. Each test says what to type,
what you should see, and why it matters. Work down the list; later tests assume
the earlier ones passed.

Set up once:

```powershell
python make_testdata.py
```

That builds `share/` (what the server offers) and `outbox/` (what you upload).
Re-run it with `--clean` any time you want a fresh start.

## The reference data

These checksums are fixed — the generator is seeded, so you get the same bytes
on both computers. Use them to prove a transfer was faithful.

| File | Size | SHA-256 starts with |
| --- | ---: | --- |
| `share/readme.txt` | 169 B | `abe87e97b2a104e5` |
| `share/unicode.txt` | 324 B | `775b8d0a2e8d8c5c` |
| `share/lecture/notes.md` | 285 B | `cad5a5425daba3ad` |
| `share/lecture/checksums.md` | 305 B | `2229bd940486d061` |
| `share/sample.bin` | 64 KB | `924b0c5c4e07ac10` |
| `share/photo.jpg.bin` | 2 MB | `f1c32679d3b4f165` |
| `share/big.bin` | 40 MB | `0af5b04582f01400` |
| `share/zero.dat` | 0 B | `e3b0c44298fc1c14` |
| `outbox/homework.txt` | 151 B | `9277760ead004c2c` |
| `outbox/report.md` | 143 B | `78cfa4138a643fda` |
| `outbox/upload_me.bin` | 5 MB | `b1ac739e72f1681c` |

To check a file yourself at any point:

```powershell
Get-FileHash downloads\big.bin -Algorithm SHA256
```

---

## Part A — one computer (start here)

Two terminals on the same machine. Everything works over `127.0.0.1`, so you
can do the whole of Part A before touching a second computer.

### A1. The server starts and shows a code

Terminal 1:

```powershell
python kuft.py serve
```

**Expect** a box with the share path, `TLS 1.3`, a `connect` command to copy,
a pairing code like `6D66-63UE-L7M6`, and a fingerprint. Leave this running.

### A2. First connection asks for the code

Terminal 2:

```powershell
python kuft.py connect 127.0.0.1
```

**Expect** the fingerprint to be shown, then a hidden `pairing code:` prompt.
Type the code from Terminal 1 (dashes and case do not matter). You should get
`OK paired with 127.0.0.1:5150` and land at a `kuft />` prompt.

> Compare the fingerprint on screen with the server's before typing the code.
> That comparison is the whole point of the pairing step.

### A3. Look around

At the `kuft />` prompt:

```text
help
ls
ls lecture
info
```

**Expect** `help` to list commands; `ls` to show 8 entries with sizes;
`info` to report `TLSv1.3`, a cipher name, and the fingerprint.

### A4. Inspect before downloading

```text
stat big.bin
```

**Expect** `200 OK`, size `41943040 octets`, and a checksum starting
`sha256=0af5b04582f01400`. Nothing was transferred — only metadata.

### A5. Download, with a progress bar

```text
get big.bin
```

**Expect** a moving progress bar with a rate and ETA, then `200 OK`, then
`saved to downloads\big.bin` and `checksum verified`.

Confirm it independently:

```powershell
Get-FileHash downloads\big.bin -Algorithm SHA256
```

**Expect** it to start `0AF5B04582F01400`.

### A6. Download under another name

```text
get lecture/notes.md transport-notes.md
```

**Expect** `saved to downloads\transport-notes.md`.

### A7. Non-ASCII content survives

```text
get unicode.txt
```

Then open `downloads\unicode.txt` in Notepad or VS Code. **Expect** the Thai,
Japanese, Greek and emoji lines to be intact. If your terminal shows `???`
that is the console font, not the file — check in an editor.

### A8. Upload

```text
put outbox/homework.txt
```

**Expect** `201 CREATED`. Then `ls` should show `homework.txt` on the server.

### A9. Uploading over an existing file is refused

```text
put outbox/homework.txt
```

**Expect** it to fail immediately with `already exists ... add --force`.
Note it fails *before* sending the file — nothing is uploaded twice.

### A10. Force the overwrite

```text
put outbox/homework.txt --force
```

**Expect** `200 OK` (not `201` — 200 means it replaced something).

### A11. Rename and delete

```text
mv homework.txt hw-final.txt
ls
rm hw-final.txt
ls
```

**Expect** `200 OK`, then the new name in the listing, then `204 NO CONTENT`,
then it gone.

### A12. Directories

```text
mkdir uploads
cd uploads
pwd
put outbox/report.md
ls
cd ..
rm uploads
```

**Expect** `201 CREATED`; the prompt to become `kuft /uploads>`; the upload to
land inside; and the final `rm` to fail with `409 CONFLICT` because the
directory is not empty. Delete the file first, then the directory.

### A13. Errors you should be able to trigger

Type each and check the status code.

| Type this | Expect |
| --- | --- |
| `get nothing.txt` | `404 NOT FOUND` |
| `stat nothing.txt` | `404 NOT FOUND` |
| `ls nowhere` | `404 NOT FOUND` |
| `get ../../users.json` | `403 FORBIDDEN` — path escapes the share |
| `get ..\..\Windows\win.ini` | `403 FORBIDDEN` |
| `rm /` | `403 FORBIDDEN` — refuses to delete the share root |
| `mkdir lecture` | `409 CONFLICT` — already exists |
| `rm lecture` | `409 CONFLICT` — not empty |
| `put outbox/homework.txt --corrupt` | `422 CHECKSUM MISMATCH` |

A13 last row matters most: `--corrupt` sends a deliberately wrong checksum.
**Expect** `422`, and then `ls` should show **no** partial file left behind —
the server writes to a temp file and only renames it after the checksum
passes.

### A14. Leave politely

```text
quit
```

**Expect** `disconnected`, and the server terminal to log the disconnect.

### A15. The second connection needs no code

```powershell
python kuft.py connect 127.0.0.1
```

**Expect** no prompt at all — straight to
`OK authenticated (fingerprint matches the pinned one)`. That is the pinning
working. Type `quit` to leave.

---

## Part B — security behaviour

These are the tests worth showing in a report or on video.

### B1. A wrong pairing code is rejected

```powershell
python kuft.py forget 127.0.0.1
python kuft.py connect 127.0.0.1 --code AAAA-BBBB-CCCC
```

**Expect** `pairing failed -- that code does not match this server`, after a
deliberate one-second pause. The pause is there so guessing is slow.

Then pair properly again:

```powershell
python kuft.py connect 127.0.0.1
```

### B2. A changed certificate stops everything

This simulates someone intercepting the connection. Rotate the server's
identity so it presents a different certificate:

```powershell
# Terminal 1: stop the server with Ctrl+C, then
Rename-Item $HOME\.kuft\server_cert.pem server_cert.pem.bak
Rename-Item $HOME\.kuft\server_key.pem server_key.pem.bak
python kuft.py serve
```

```powershell
# Terminal 2
python kuft.py connect 127.0.0.1
```

**Expect** a red `PINNED CERTIFICATE MISMATCH`, both fingerprints printed
side by side, and **no prompt to continue anyway**. Exit code is `2`.

Put it back:

```powershell
# Ctrl+C the server first
Remove-Item $HOME\.kuft\server_cert.pem, $HOME\.kuft\server_key.pem
Rename-Item $HOME\.kuft\server_cert.pem.bak server_cert.pem
Rename-Item $HOME\.kuft\server_key.pem.bak server_key.pem
python kuft.py serve
```

### B3. The traffic really is encrypted

With the server running, start a client and run `info`.

**Expect** `tls TLSv1.3` and a cipher such as `TLS_AES_256_GCM_SHA384`.
The server refuses anything below TLS 1.3, so there is no downgrade to test.

If you want to see it on the wire, run Wireshark on the loopback adapter,
filter `tcp.port == 5150`, and do a `get readme.txt`. **Expect** to see
`Application Data` records only — the words from `readme.txt` never appear.

### B4. Read-only mode

```powershell
# Terminal 1, Ctrl+C then:
python kuft.py serve --read-only
```

From a client, `ls` and `get readme.txt` should work; `put`, `rm`, `mkdir`
and `mv` should all return `403 FORBIDDEN`.

### B5. Rate limiting

```powershell
python kuft.py serve --rate-limit 5
```

From the client, type `stat readme.txt` quickly more than five times within
ten seconds. **Expect** the later ones to return `429 TOO MANY REQUESTS`.

### B6. Capacity limit

```powershell
python kuft.py serve --max-clients 1
```

Connect one client and leave it at the prompt. Open a third terminal and
connect a second client. **Expect** the second to be refused with
`503 SERVICE UNAVAILABLE`.

---

## Part C — the real thing: two computers

This is what the tool is for. Both machines need Python 3.10+ and the
`cryptography` package; run `python kuft.py doctor` on each first.

### C1. Find the server's address

On the **sending** computer:

```powershell
python kuft.py serve
```

The banner prints the exact command to run, including the LAN address, e.g.
`python kuft.py connect 192.168.1.114 --port 5150`.

If it shows only `127.0.0.1`, find the address manually:

```powershell
ipconfig | Select-String IPv4
```

### C2. Let it through the firewall

The first time you run the server, Windows will ask. **Allow it on private
networks.** If you dismissed that dialog, run once as Administrator:

```powershell
New-NetFirewallRule -DisplayName "KUFT" -Direction Inbound -Protocol TCP -LocalPort 5150 -Action Allow -Profile Private
```

### C3. Check the two machines can see each other

On the **receiving** computer:

```powershell
Test-NetConnection 192.168.1.114 -Port 5150
```

**Expect** `TcpTestSucceeded : True`. If it is False, the firewall or the
network is blocking you — fix that before going on. Both machines must be on
the same network, and many university and café Wi-Fi networks isolate clients
from each other, which will block this.

### C4. Pair and transfer

On the receiving computer:

```powershell
python kuft.py connect 192.168.1.114
```

Read the pairing code off the *other* machine's screen and type it. Then:

```text
ls
get big.bin
quit
```

**Expect** the same `checksum verified` line as in A5. Compare the hash on
both machines:

```powershell
Get-FileHash downloads\big.bin -Algorithm SHA256   # receiving machine
Get-FileHash share\big.bin -Algorithm SHA256       # sending machine
```

**Expect** them to be identical. That is the end-to-end proof.

### C5. Send a file the other way

The receiving computer can upload too:

```text
put outbox/upload_me.bin
```

**Expect** `201 CREATED`, and the file to appear in the sender's `share/`.

### C6. Interrupted transfer resumes

Start a big download and kill it halfway:

```text
get big.bin
```

Press `Ctrl+C` while the bar is moving. You will see a `.part` file in
`downloads/`. Now run the same command again:

```text
get big.bin
```

**Expect** `resuming at <size>` and the transfer to pick up where it stopped,
then still report `checksum verified` — the whole assembled file is hashed,
not just the resumed part.

---

## Part D — automated tests

The suite covers the same ground without typing:

```powershell
python -m unittest discover -s tests -v
```

**Expect** `Ran 68 tests` and `OK`. It uses a temporary `KUFT_HOME`, so it
never touches your real keys or paired hosts.

---

## Recording a result

If you need to hand in evidence, this captures a full session to a file:

```powershell
python kuft.py connect 127.0.0.1 --no-color | Tee-Object -FilePath session.txt
```

`--no-color` keeps ANSI escape codes out of the saved text.
