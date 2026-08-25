"""Find a Python that can actually run KUFT, and re-launch into it.

The machine this was built on has two interpreters: an MSYS2 build first on
PATH with no pip, and a python.org build that has ``cryptography``.  Typing
``python kuft.py`` picks the wrong one.  Rather than making that the user's
problem, the launcher checks whether the current interpreter can import
``cryptography`` and, if not, hands off to one that can.

Set ``KUFT_NO_REEXEC=1`` to switch the hand-off off (the test suite does).
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

REQUIRED = "cryptography"
_PROBE = "import cryptography, sys; sys.stdout.write(cryptography.__version__)"


def have_dependency() -> bool:
    try:
        import cryptography  # noqa: F401
    except ImportError:
        return False
    return True


def _candidate_interpreters() -> list[Path]:
    """Every python on this machine worth probing, best guesses first."""
    seen: list[Path] = []

    def add(raw: str | Path | None) -> None:
        if not raw:
            return
        path = Path(raw)
        if path.exists() and path not in seen:
            seen.append(path)

    local = os.environ.get("LOCALAPPDATA")
    if local:
        add(Path(local) / "Microsoft" / "WindowsApps" / "python.exe")
        for version in ("313", "312", "311", "310"):
            add(Path(local) / "Programs" / "Python" / f"Python{version}" / "python.exe")

    for root in ("C:/Python313", "C:/Python312", "C:/Python311", "C:/Python310"):
        add(Path(root) / "python.exe")

    # Anything else on PATH, minus the interpreter we are already running.
    from shutil import which

    for name in ("python3", "python", "py"):
        found = which(name)
        if found and Path(found).resolve() != Path(sys.executable).resolve():
            add(found)

    return seen


def find_capable_interpreter() -> Path | None:
    for candidate in _candidate_interpreters():
        try:
            probe = subprocess.run(
                [str(candidate), "-c", _PROBE],
                capture_output=True,
                timeout=20,
                text=True,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        if probe.returncode == 0 and probe.stdout.strip():
            return candidate
    return None


def ensure_dependencies(argv: list[str]) -> None:
    """Return normally if we can run; otherwise re-exec or explain and exit."""
    if have_dependency() or os.environ.get("KUFT_NO_REEXEC"):
        return

    interpreter = find_capable_interpreter()
    if interpreter is None:
        _explain_and_exit()

    script = Path(__file__).resolve().parents[2] / "kuft.py"
    env = dict(os.environ, KUFT_REEXECED="1")
    if os.environ.get("KUFT_REEXECED"):
        # We already tried this once; a loop would be worse than an error.
        _explain_and_exit()

    completed = subprocess.run([str(interpreter), str(script), *argv], env=env)
    raise SystemExit(completed.returncode)


def _explain_and_exit() -> None:
    print()
    print(f"  KUFT needs the '{REQUIRED}' package, and no interpreter here has it.")
    print()
    print("  Fix it with one of these:")
    print()
    print(f"    python -m pip install {REQUIRED}")
    print(f"    py -m pip install {REQUIRED}")
    print()
    print(f"  This interpreter is: {sys.executable}")
    print("  If it has no pip, install Python from python.org and use that one.")
    print()
    raise SystemExit(3)


def doctor() -> int:
    """Report on the environment -- the thing to run when something is off."""
    print()
    print("  KUFT environment check")
    print("  " + "-" * 52)
    print(f"  running on      {sys.executable}")
    print(f"  version         {sys.version.split()[0]}")

    if sys.version_info < (3, 10):
        print("  python version  TOO OLD -- KUFT needs 3.10 or newer")
    else:
        print("  python version  OK")

    try:
        import ssl

        print(f"  tls library     {ssl.OPENSSL_VERSION}")
        has_tls13 = ssl.HAS_TLSv1_3
        print(f"  tls 1.3         {'OK' if has_tls13 else 'MISSING -- KUFT requires it'}")
    except ImportError:
        print("  tls library     MISSING -- this Python was built without ssl")

    if have_dependency():
        import cryptography

        print(f"  cryptography    OK ({cryptography.__version__})")
        verdict = "  Ready. Run:  python kuft.py serve"
    else:
        print("  cryptography    MISSING here")
        other = find_capable_interpreter()
        if other:
            print(f"  fallback        found at {other}")
            verdict = "  Ready. kuft.py will use the fallback interpreter automatically."
        else:
            print("  fallback        none found")
            verdict = f"  Not ready. Install it:  python -m pip install {REQUIRED}"

    print("  " + "-" * 52)
    print(verdict)
    print()
    return 0
