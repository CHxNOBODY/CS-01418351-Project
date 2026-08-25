# Transport layer

TCP gives us an ordered, reliable byte stream. KUFT leans on that:
the protocol never renumbers or retransmits anything itself.

* three-way handshake before any KUFT byte is sent
* TLS 1.3 handshake on top of that
* only then does `HELLO * KUFT/2.0` go out
