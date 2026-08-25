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

    child = subprocess.Popen([str(interpreter), str(script), *argv], env=env)
    _tie_lifetime_to_ours(child.pid)
    try:
        raise SystemExit(child.wait())
    except KeyboardInterrupt:
        # In a real console the Ctrl+C reached the child as well, so give it a
        # moment to shut down on its own terms before insisting.
        try:
            code = child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            child.terminate()
            code = child.wait()
        raise SystemExit(code) from None


# The job handle has to outlive this function: Windows kills the job when its
# last handle closes, which is exactly the guarantee we want at exit.
_JOB_HANDLE = None


def _tie_lifetime_to_ours(pid: int) -> None:
    """Make the child die with us, so an interrupt cannot orphan the server.

    The launcher and the interpreter it hands off to are two processes.  When
    an interrupt reaches only the launcher -- which is what happens in
    terminals that deliver a POSIX signal instead of a console control event --
    the server carries on running invisibly and keeps the port bound, so the
    next ``serve`` fails with 'cannot bind'.  A job object with
    KILL_ON_JOB_CLOSE ties the two together for every exit path, including a
    hard kill of the launcher.
    """
    global _JOB_HANDLE
    if os.name != "nt":
        return
    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateJobObjectW.restype = wintypes.HANDLE
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

        class _BasicLimits(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", ctypes.c_int64),
                ("PerJobUserTimeLimit", ctypes.c_int64),
                ("LimitFlags", wintypes.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD),
            ]

        class _IoCounters(ctypes.Structure):
            _fields_ = [(name, ctypes.c_uint64) for name in (
                "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                "ReadTransferCount", "WriteTransferCount", "OtherTransferCount",
            )]

        class _ExtendedLimits(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", _BasicLimits),
                ("IoInfo", _IoCounters),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        job = kernel32.CreateJobObjectW(None, None)
        if not job:
            return
        limits = _ExtendedLimits()
        limits.BasicLimitInformation.LimitFlags = 0x2000  # KILL_ON_JOB_CLOSE
        if not kernel32.SetInformationJobObject(
            job, 9, ctypes.byref(limits), ctypes.sizeof(limits)
        ):
            kernel32.CloseHandle(job)
            return
        handle = kernel32.OpenProcess(0x0100 | 0x0001, False, pid)  # SET_QUOTA|TERMINATE
        if not handle:
            kernel32.CloseHandle(job)
            return
        assigned = kernel32.AssignProcessToJobObject(job, handle)
        kernel32.CloseHandle(handle)
        if not assigned:
            kernel32.CloseHandle(job)
            return
        _JOB_HANDLE = job
    except Exception:
        # Losing the safety net is not worth refusing to run over.
        return


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
