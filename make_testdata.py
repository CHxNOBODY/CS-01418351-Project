#!/usr/bin/env python3
"""Build the sample files used by MANUAL-TESTS.md.

    python make_testdata.py            create everything
    python make_testdata.py --clean    delete it and start over

Files land in two places: ``share/`` is what the server offers, ``outbox/`` is
what you upload from.  Both are regenerated from scratch, so a test run that
deletes or overwrites something is easy to reset.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import random
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SHARE = ROOT / "share"
OUTBOX = ROOT / "outbox"
DOWNLOADS = ROOT / "downloads"

# Deterministic, so the checksums below are the same on both machines.
SEED = 20260825


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def write_random(path: Path, size: int, seed: int) -> None:
    """A pseudo-random binary file, written in blocks so memory stays flat."""
    path.parent.mkdir(parents=True, exist_ok=True)
    rng = random.Random(seed)
    with open(path, "wb") as handle:
        remaining = size
        while remaining > 0:
            block = min(1 << 20, remaining)
            handle.write(rng.randbytes(block))
            remaining -= block


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def build() -> list[Path]:
    made: list[Path] = []

    # --- what the server offers -------------------------------------------
    write_text(
        SHARE / "readme.txt",
        "KUFT/2.0 test share\n"
        "===================\n\n"
        "If you can read this on the other computer, the transfer worked.\n"
        "Every file here has a known SHA-256; see MANUAL-TESTS.md.\n",
    )
    made.append(SHARE / "readme.txt")

    write_text(
        SHARE / "unicode.txt",
        "Encoding check -- these must survive the trip byte for byte.\n\n"
        "Thai      สวัสดีชาวโลก\n"
        "Japanese  こんにちは世界\n"
        "Greek     Καλημέρα κόσμε\n"
        "Emoji     ok -> \N{PARTY POPPER} \N{ROCKET} \N{LOCK}\n"
        "Maths     ∑ ∞ ≈ ± √2 ≈ 1.41421\n"
        "Quotes    “curly” and ‘single’ and an em--dash — here\n",
    )
    made.append(SHARE / "unicode.txt")

    write_text(
        SHARE / "lecture" / "notes.md",
        "# Transport layer\n\n"
        "TCP gives us an ordered, reliable byte stream. KUFT leans on that:\n"
        "the protocol never renumbers or retransmits anything itself.\n\n"
        "* three-way handshake before any KUFT byte is sent\n"
        "* TLS 1.3 handshake on top of that\n"
        "* only then does `HELLO * KUFT/2.0` go out\n",
    )
    made.append(SHARE / "lecture" / "notes.md")

    write_text(
        SHARE / "lecture" / "checksums.md",
        "# Why every transfer carries a SHA-256\n\n"
        "TCP's checksum is 16 bits and covers accidental corruption only.\n"
        "It says nothing about a file that was truncated by a crash, or\n"
        "altered on the disk it came from. A SHA-256 over the payload closes\n"
        "both gaps, and costs one pass over data we are reading anyway.\n",
    )
    made.append(SHARE / "lecture" / "checksums.md")

    # A small binary, a medium one, and one big enough that the progress bar,
    # the chunked streaming and resume all actually get exercised.
    write_random(SHARE / "sample.bin", 64 * 1024, SEED)
    made.append(SHARE / "sample.bin")
    write_random(SHARE / "photo.jpg.bin", 2 * 1024 * 1024, SEED + 1)
    made.append(SHARE / "photo.jpg.bin")
    write_random(SHARE / "big.bin", 40 * 1024 * 1024, SEED + 2)
    made.append(SHARE / "big.bin")

    (SHARE / "empty_dir").mkdir(parents=True, exist_ok=True)

    write_text(SHARE / "zero.dat", "")
    made.append(SHARE / "zero.dat")

    # --- what you upload from ---------------------------------------------
    write_text(
        OUTBOX / "homework.txt",
        "CS-01418351 -- Project 1\n"
        "Uploaded from the client to prove PUT works.\n"
        "Change a character in this file and upload it again to see 409, then --force.\n",
    )
    made.append(OUTBOX / "homework.txt")

    write_text(
        OUTBOX / "report.md",
        "# Findings\n\n"
        "| Test | Expected | Got |\n"
        "| --- | --- | --- |\n"
        "| download | 200 | |\n"
        "| upload | 201 | |\n"
        "| overwrite without --force | 409 | |\n",
    )
    made.append(OUTBOX / "report.md")

    write_random(OUTBOX / "upload_me.bin", 5 * 1024 * 1024, SEED + 3)
    made.append(OUTBOX / "upload_me.bin")

    DOWNLOADS.mkdir(parents=True, exist_ok=True)
    return made


def main() -> int:
    parser = argparse.ArgumentParser(description="Create KUFT test data.")
    parser.add_argument("--clean", action="store_true", help="delete and rebuild")
    args = parser.parse_args()

    if args.clean:
        for folder in (SHARE, OUTBOX):
            if folder.exists():
                shutil.rmtree(folder)
        print(f"  removed {SHARE.name}/ and {OUTBOX.name}/")

    made = build()

    print()
    print("  Test data ready.")
    print()
    width = max(len(str(p.relative_to(ROOT))) for p in made)
    print(f"  {'FILE'.ljust(width)}  {'SIZE':>10}  SHA-256 (first 16)")
    print(f"  {'-' * width}  {'-' * 10}  {'-' * 18}")
    for path in made:
        rel = str(path.relative_to(ROOT)).replace(os.sep, "/")
        size = path.stat().st_size
        print(f"  {rel.ljust(width)}  {size:>10}  {sha256(path)[:16]}")
    print()
    print(f"  share/    {len(list(SHARE.rglob('*')))} entries -- what the server offers")
    print(f"  outbox/   {len(list(OUTBOX.rglob('*')))} entries -- what you upload")
    print()
    print("  Next:  python kuft.py serve")
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
