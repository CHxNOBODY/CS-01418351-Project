# Lab 03 – DNS and HTTP: Answers

> Prerequisites: be on KUWIN or KU VPN, and set primary DNS = **158.108.16.155** (secondary 1.1.1.1 or 8.8.8.8).
> Start the Wireshark capture **before** each step. Use filter `dns` or `http`.
> `./lab03_solve.sh` runs every command below and prints all flags. Run it with Wireshark capturing
> to get the screenshots. **[FILL]** = value from your capture.

## Warm-up Questions

### 1. `dig test.network.lab ANY` (filter `dns`)

**a. Record type.** The query asks for type **ANY (255)**. In Wireshark, open the query packet and
expand *Domain Name System → Queries → test.network.lab: type ANY, class IN*.
The answer section of the response shows which record type(s) actually came back
(expected: **A** record, shown as `type A, class IN, addr …`) **[confirm in capture]**.

**b. Resolved IP.** In the response, look under *Answers → test.network.lab: type A … addr* **[FILL IP]**.

**c. Transport and port.** **UDP**, destination port **53** (shown in the *User Datagram Protocol* layer:
`Dst Port: 53` on the query, `Src Port: 53` on the response). DNS switches to TCP/53 only for large or
truncated responses and zone transfers.

**d. Number of packets.** **2**: one standard query and one standard query response. They match by the
same *Transaction ID*.

📷 Screenshot: `dns` filter showing query and response, with the response expanded.

### 2. `v10.network.lab` vs `v11.network.lab` (filter `http`, then `tcp`)
Use a browser so the page's embedded objects are fetched too. Alternatively, ask curl for two URLs in one
command (see script).

**a. Versions.** `v10.network.lab` reports **HTTP/1.0** (status line `HTTP/1.0 200 OK`).
`v11.network.lab` reports **HTTP/1.1** (`HTTP/1.1 200 OK`).

**b. Single TCP connection: `v11` (HTTP/1.1, persistent connection).**
All GETs for the page and its objects share **one `tcp.stream` index**: one 3-way handshake (SYN, SYN-ACK, ACK),
then several request/response pairs on the same client port. The response has
`Connection: keep-alive` or no `Connection: close` header (persistence is the HTTP/1.1 default).
curl shows `Re-using existing connection`.

**c. New TCP connection per object: `v10` (HTTP/1.0, non-persistent).**
Each object gets its **own `tcp.stream`**, a new SYN/SYN-ACK/ACK, a different client source port, and a
FIN after one response. The server sends `Connection: close`.
Tip: *Statistics → Conversations → TCP* shows several conversations for v10 and one for v11.

📷 Screenshots: the `tcp.stream` column or Conversations window for each host.

### 3. `cache.network.lab` twice → `304 Not Modified`
- The first response, **200 OK**, carries the validator **`Last-Modified: <date>`** (and/or **`ETag: "<tag>"`**).
- The browser caches the object. The second request sends the conditional header
  **`If-Modified-Since: <that date>`** (and/or **`If-None-Match: "<tag>"`**).
- The resource has not changed, so the server replies **`304 Not Modified`** with no body.

So: request header **If-Modified-Since** (or If-None-Match) causes the 304. It is made possible by
**Last-Modified** (or ETag) in the first 200 OK. **[confirm which pair your capture shows]**

Browser: load the page, then press normal reload (not Ctrl+F5). With curl:
```bash
curl -i http://cache.network.lab/
```
```bash
curl -i -H 'If-Modified-Since: <Last-Modified value>' http://cache.network.lab/
```

📷 Screenshot: the 200 (showing Last-Modified/ETag) and the 304 request (showing If-Modified-Since).

## Flag Challenges

### 1. `flag.network.lab` (not an A record)
How: `dig flag.network.lab A` returns no answer. Query by type, or use ANY:
```bash
dig flag.network.lab ANY
```
```bash
dig flag.network.lab TXT
```
The record type is most likely **TXT** (TXT holds free text) **[confirm]**. In Wireshark, the response's
*Answers* show `type TXT … TXT: FLAG{…}`.
**Flag: [FILL]**

### 2. Domain of the name server
How: ask for the **NS** record of the zone:
```bash
dig network.lab NS
```
In Wireshark, *Answers → network.lab: type NS, class IN, ns <name-server-domain>*.
(If the question means the NS for flag.network.lab, use `dig flag.network.lab NS`.)
**Flag: FLAG{[FILL ns domain]}**

### 3. `cname.network.lab`
How: `dig cname.network.lab` returns a **CNAME** (alias) pointing to another name. Query that
target, then repeat until the chain ends. The last name usually holds the flag in a TXT record
(`dig <last-name> TXT`). The script follows the chain automatically.
Chain: `cname.network.lab → [FILL] → … → [FILL]`
**Flag: [FILL]**

### 4. `GET /start` on `v11.network.lab` → 301
```bash
printf 'GET /start HTTP/1.1\r\nHost: v11.network.lab\r\nConnection: close\r\n\r\n' | nc v11.network.lab 80
```
(or `curl -i http://v11.network.lab/start`, without `-L`). The response is `HTTP/1.1 301 Moved Permanently`
with a `Location:` header. One custom header (e.g. `X-Flag:`) holds the flag.
In Wireshark, filter `http.response.code == 301` and expand the HTTP headers.
**Flag: [FILL]**  Location: **[FILL]**

### 5. Follow the Location (the PDF says "challenge no. 3", but it means no. 4)
Open the Location URL. The page references several objects (img/css/js/txt). Fetch each one. Only one
200 OK body contains `FLAG{…}`. In Wireshark, filter `http.response.code == 200`, find the object, and
use *Follow → HTTP Stream* or the *Line-based text data* pane.
Object: **[FILL path]**   **Flag: [FILL]**

📷 For every flag: a screenshot of the packet with the flag field highlighted.
