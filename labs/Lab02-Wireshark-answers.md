# Lab 02 – Basic Wireshark: Answers

> Items marked **[FILL]** come from your own capture. Capture on your Wi-Fi/Ethernet
> interface (no VPN), open `http://network.nk-n.com` (http, not https), stop the capture, filter `http`.

## 7.1 Warm-up Questions

### 1. Interesting protocols (unfiltered capture)

| Protocol | What it is used for |
|---|---|
| **DNS** | Translates host names (e.g. `network.nk-n.com`) into IP addresses. Uses UDP port 53. |
| **TCP** | Reliable, ordered, connection-oriented transport. Carries HTTP and TLS. Uses a 3-way handshake (SYN, SYN-ACK, ACK). |
| **HTTP** | Application protocol for web pages. Here it runs unencrypted, so Wireshark can show its headers and body. |
| **TLSv1.2 / TLSv1.3** | Encrypts HTTPS traffic from other tabs and background apps. Only "Application Data" is visible. |
| **QUIC** | UDP-based transport used by HTTP/3 (Google, YouTube, etc.) on UDP 443. |
| **ARP** | Maps an IPv4 address to a MAC address on the local network (e.g. finding the gateway's MAC). |
| **ICMP / ICMPv6** | Network control and error messages (ping, unreachable). ICMPv6 also does Neighbor Discovery. |
| **MDNS / SSDP / LLMNR** | Local-network service and device discovery (printers, Chromecast, AirPlay, UPnP). |
| **NTP** | Keeps the system clock in sync. Uses UDP port 123. |
| **DHCP** | Gives the host its IP address, gateway and DNS server. |

*(Keep only the ones you actually see in your capture.)*

📷 Screenshot: unfiltered packet list.

### 2. Time between the HTTP GET and its response
Time = (Time of `HTTP/1.1 200 OK`) − (Time of `GET /`) = **[FILL] s**.
Wireshark also shows this directly: expand the response's HTTP layer and read
`[Time since request: … seconds]` (field `http.time`).

📷 Screenshot: `http`-filtered list with both packets and the Time column visible.

### 3. Browser (User-Agent)
Expand **Hypertext Transfer Protocol** in the GET packet and read the `User-Agent:` line.
Answer: **[FILL]**. For example, `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/… Safari/537.36` means **Google Chrome** on Windows.
(Chrome, Edge and Safari all start with "Mozilla/5.0" for historical compatibility. Look at the last tokens: `Edg/` means Edge, `Firefox/` means Firefox, and `Chrome/` without `Edg/` means Chrome.)

📷 Screenshot: expanded HTTP header with User-Agent highlighted.

## 7.2 Flag Challenges

### Challenge 1 – Destination Port
Select the `GET` packet, expand **Transmission Control Protocol**, and read `Destination Port`.
(Quick filter: `http.request`. You can also add `tcp.dstport` as a column.)
**Flag: FLAG{[FILL port number]}**. Write only the number if your instructor wants the plain value.
Note: if Wireshark doesn't label the packet as HTTP because the port isn't 80, right-click it,
choose **Decode As… → HTTP**, then filter `http`.

📷 Screenshot: TCP header of the GET with Destination Port highlighted.

### Challenge 2 – Response Header
Select the `HTTP/1.1 200 OK` packet, expand **Hypertext Transfer Protocol**, and look for a non-standard
header (often `X-Flag:` or similar). **Flag: [FILL]**

📷 Screenshot: expanded response headers with the custom header highlighted.

### Challenge 3 – Response Body
Right-click the response, choose **Follow → HTTP Stream**, and search (Find) for `FLAG{`. It may be inside an HTML
comment `<!-- … -->` or hidden text. **Flag: [FILL]**

📷 Screenshot: Follow HTTP Stream window with the flag highlighted.
