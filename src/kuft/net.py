"""Addresses, and what to say when one of them will not answer.

The most common way a two-machine transfer fails is not a bug in KUFT: it is
a 192.168.x.x address typed on a machine that is not on that 192.168 network.
A private address means nothing outside the network it belongs to, so the
packets leave for a machine that is not there and the connection sits until it
times out.  ``diagnose`` turns that silence into an explanation.
"""

from __future__ import annotations

import errno
import ipaddress
import socket

def remote_advice(port: int) -> list[str]:
    """What to do when the two machines are genuinely on different networks.

    None of it is a KUFT setting: a private address cannot be made routable by
    the program that dials it, so every route out is something the user has to
    arrange around the program.
    """
    return [
        "Reaching a machine on a different network needs one of these:",
        "  - a VPN that puts both machines on one network (Tailscale, ZeroTier);",
        "    connect to the address that VPN gives the server, not its LAN one",
        f"  - port forwarding for TCP {port} on the server's router; connect to",
        "    the server's public address, from whatismyipaddress.com there",
        f"  - a tunnel, e.g. 'ngrok tcp {port}'; connect to the host and port it prints",
    ]


def local_addresses() -> list[str]:
    """Addresses a client on the same network could actually reach us on."""
    found: list[str] = []
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.settimeout(0.2)
        probe.connect(("10.255.255.255", 1))  # never sends a packet
        found.append(probe.getsockname()[0])
        probe.close()
    except OSError:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            addr = info[4][0]
            if addr not in found and not addr.startswith("127."):
                found.append(addr)
    except OSError:
        pass
    return found


def _as_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None  # a name, not a literal address


def _shares_network(target: str, ours: str) -> bool:
    """A guess at whether two addresses sit on the same network.

    The real answer needs the netmask of every interface, which is not worth
    the platform-specific machinery here.  Comparing the first three octets
    matches the /24 that home and campus networks almost always use, and the
    caller only uses the answer to choose which advice to print.
    """
    return target.split(".")[:3] == ours.split(".")[:3]


def diagnose(host: str, port: int, exc: BaseException) -> list[str]:
    """Lines explaining a failed connection, most useful first."""
    address = _as_ip(host)
    ours = local_addresses()
    lines: list[str] = []

    if isinstance(exc, socket.gaierror):
        return [
            f"the name {host!r} did not resolve to any address",
            "check the spelling, or use the numeric address the server printed",
        ]

    if address is not None and address.is_loopback:
        return [
            f"{host} always means 'this same computer', never the other one",
            "run 'python kuft.py connect <the address the server printed>'",
        ]

    if address is not None and (address.is_private or address.is_link_local):
        lines.append(
            f"{host} is a private address: it only exists inside the server's "
            "own network"
        )
        if ours and not any(_shares_network(host, mine) for mine in ours):
            lines.append(
                f"this machine is on {', '.join(ours)} -- a different network, "
                "so nothing here can route to it"
            )
            lines.extend(remote_advice(port))
            return lines
        lines.append("both machines must be on the same Wi-Fi or switch for it to work")

    if isinstance(exc, TimeoutError):  # socket.timeout is an alias of this
        lines += [
            "nothing answered at all, which usually means the packets never "
            "arrived: wrong address, the server is not running, or a firewall "
            "is dropping them silently",
            f"test the path first:  Test-NetConnection {host} -Port {port}",
        ]
    elif getattr(exc, "errno", None) == errno.ECONNREFUSED:
        lines += [
            f"{host} answered and refused: the machine is reachable, but nothing "
            f"is listening on port {port}",
            "start the server there, or pass the --port it is actually using",
        ]
    elif getattr(exc, "errno", None) in (errno.EHOSTUNREACH, errno.ENETUNREACH):
        lines.append("this machine has no route to that address at all")
    else:
        lines.append(
            "check the address, that the server is running, and the firewall"
        )

    if address is not None and address.is_global:
        lines.append(
            "for a public address the server's router must forward TCP "
            f"{port} to it"
        )
    return lines
