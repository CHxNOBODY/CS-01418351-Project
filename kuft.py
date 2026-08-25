#!/usr/bin/env python3
"""KUFT/2.0 -- encrypted file transfer between two computers, from a terminal.

    python kuft.py serve                 share this machine's ./share directory
    python kuft.py connect 192.168.1.42  open a session against another machine
    python kuft.py doctor                check this machine can run KUFT
    python kuft.py id                    show this machine's code + fingerprint
    python kuft.py hosts                 list servers already paired with
    python kuft.py forget <host>         un-pin a server

Run it with no arguments for a short tour.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from kuft.bootstrap import doctor, ensure_dependencies  # noqa: E402

COMMANDS = ("serve", "connect", "doctor", "id", "hosts", "forget")

TOUR = """
  KUFT/2.0 -- encrypted file transfer over TLS 1.3

  On the computer that HAS the files:

      python kuft.py serve

    It prints an address and a pairing code. Put the files you want to
    send into the 'share' folder next to this script.

  On the computer that WANTS the files:

      python kuft.py connect <address shown by the server>

    Type the pairing code once. From then on that server is remembered.
    At the kuft> prompt:  ls, get <file>, put <file>, help, quit

  Other commands

      python kuft.py doctor          check this machine is ready
      python kuft.py id              show this machine's code and fingerprint
      python kuft.py hosts           servers this machine has paired with
      python kuft.py forget <host>   forget one, e.g. after a server rebuild

  Add --help to any command for its options.
"""


def cmd_id(argv: list[str]) -> int:
    from kuft import term
    from kuft.crypto import ServerIdentity, identity_dir

    rotate = "--new-code" in argv
    term.init_color("--no-color" not in argv)
    identity = ServerIdentity.load_or_create(rotate_code=rotate)
    term.banner(
        [
            term.paint("This machine's server identity", "bold"),
            "",
            "  Pairing code  " + term.paint(identity.code, "green", "bold"),
            "  Fingerprint   " + term.paint(identity.pretty_fingerprint, "grey"),
            "",
            f"  Keys stored in {identity_dir()}",
        ]
    )
    if rotate:
        term.warn("code rotated -- every previously paired client must pair again")
    return 0


def cmd_hosts(argv: list[str]) -> int:
    from kuft import term
    from kuft.crypto import KnownHosts, format_fingerprint

    term.init_color("--no-color" not in argv)
    hosts = KnownHosts()
    entries = hosts.items()
    if not entries:
        term.info("  No servers paired yet.")
        term.hint("pair one with:  python kuft.py connect <address>")
        return 0
    term.info(f"  Paired servers ({hosts.path})")
    term.table(
        ["ADDRESS", "FINGERPRINT"],
        [[host, format_fingerprint(rec.fingerprint)] for host, rec in entries],
    )
    return 0


def cmd_forget(argv: list[str]) -> int:
    import argparse

    from kuft import term
    from kuft.crypto import KnownHosts

    parser = argparse.ArgumentParser(prog="kuft.py forget")
    parser.add_argument("host")
    parser.add_argument("--port", type=int, default=5150)
    parser.add_argument("--no-color", action="store_true")
    args = parser.parse_args(argv)

    term.init_color(not args.no_color)
    if KnownHosts().forget(args.host, args.port):
        term.ok(f"forgot {args.host}:{args.port}")
        term.hint("the next connection will ask for the pairing code again")
        return 0
    term.warn(f"{args.host}:{args.port} was not in the known-hosts file")
    return 1


def main() -> int:
    argv = sys.argv[1:]

    # Line-buffer stdout. Python block-buffers when it is not a terminal, which
    # would swallow the server's log for anyone piping it to a file or to tee.
    try:
        sys.stdout.reconfigure(line_buffering=True, errors="replace")
        sys.stderr.reconfigure(errors="replace")
    except (AttributeError, OSError):
        pass

    if not argv or argv[0] in ("-h", "--help", "help"):
        print(TOUR)
        return 0

    command, rest = argv[0], argv[1:]

    if command not in COMMANDS:
        print(f"  Unknown command {command!r}.")
        print(f"  Try one of: {', '.join(COMMANDS)}")
        print("  Run 'python kuft.py' for a short tour.")
        return 2

    if command == "doctor":
        return doctor()

    # Everything below needs cryptography; hop to an interpreter that has it.
    ensure_dependencies(argv)

    if command == "serve":
        from kuft.server import main as serve_main

        return serve_main(rest)
    if command == "connect":
        from kuft.client import main as connect_main

        return connect_main(rest)
    if command == "id":
        return cmd_id(rest)
    if command == "hosts":
        return cmd_hosts(rest)
    if command == "forget":
        return cmd_forget(rest)
    return 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print()
        raise SystemExit(130)
