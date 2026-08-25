"""Terminal output: colour, progress, tables, and the transfer log.

Everything user-facing funnels through here so the whole tool looks like one
program, and so ``--no-color`` and ``NO_COLOR`` only have to be honoured once.
"""

from __future__ import annotations

import os
import shutil
import sys
import time
from datetime import datetime

_ENABLED = True


def init_color(enabled: bool) -> None:
    """Decide once whether ANSI codes are safe to emit."""
    global _ENABLED
    if not enabled or os.environ.get("NO_COLOR"):
        _ENABLED = False
        return
    _ENABLED = sys.stdout.isatty()
    if _ENABLED and os.name == "nt":
        # Ask the console host for VT processing; harmless if already on.
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        except Exception:
            pass


_CODES = {
    "dim": "2",
    "bold": "1",
    "red": "31",
    "green": "32",
    "yellow": "33",
    "blue": "34",
    "magenta": "35",
    "cyan": "36",
    "grey": "90",
}


def paint(text: str, *styles: str) -> str:
    if not _ENABLED or not styles:
        return text
    codes = ";".join(_CODES[s] for s in styles if s in _CODES)
    return f"\033[{codes}m{text}\033[0m" if codes else text


# ------------------------------------------------------------------ messages


def info(text: str) -> None:
    print(text)


def ok(text: str) -> None:
    print(f"{paint('OK', 'green', 'bold')}  {text}")


def warn(text: str) -> None:
    print(f"{paint('!', 'yellow', 'bold')}   {text}")


def fail(text: str) -> None:
    print(f"{paint('X', 'red', 'bold')}   {text}")


def hint(text: str) -> None:
    print(paint(f"    {text}", "grey"))


def rule(label: str = "") -> None:
    width = min(shutil.get_terminal_size((80, 24)).columns, 78)
    if label:
        bar = "-" * max(0, width - len(label) - 3)
        print(paint(f"-- {label} {bar}", "grey"))
    else:
        print(paint("-" * width, "grey"))


def banner(lines: list[str]) -> None:
    width = min(shutil.get_terminal_size((80, 24)).columns, 78)
    inner = width - 2
    print(paint("+" + "-" * inner + "+", "cyan"))
    for line in lines:
        pad = inner - _visible_len(line) - 2
        print(paint("|", "cyan") + " " + line + " " * max(pad, 0) + " " + paint("|", "cyan"))
    print(paint("+" + "-" * inner + "+", "cyan"))


def _visible_len(text: str) -> int:
    """Length ignoring ANSI escape sequences."""
    out, skipping = 0, False
    for ch in text:
        if skipping:
            skipping = ch != "m"
        elif ch == "\033":
            skipping = True
        else:
            out += 1
    return out


# -------------------------------------------------------------------- input


def can_hide_input() -> bool:
    """True when this process can really read keystrokes from a console.

    On Windows ``getpass`` reads the console device (CONIN$) directly and
    ignores stdin entirely.  That is fine under conhost or Windows Terminal,
    but terminals that hand native programs a pipe instead of a console --
    mintty, Git Bash, and some IDE terminals -- leave it waiting for
    keystrokes that can never arrive, so the prompt never even appears and
    nothing can be typed.  Asking the stdin handle for its console mode is
    the reliable way to tell the two apart.
    """
    if os.name != "nt":
        try:
            return sys.stdin.isatty()
        except (AttributeError, ValueError):
            return False
    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.GetStdHandle.restype = wintypes.HANDLE
        handle = kernel32.GetStdHandle(-10)  # STD_INPUT_HANDLE
        if not handle or handle == wintypes.HANDLE(-1).value:
            return False
        mode = wintypes.DWORD()
        return bool(kernel32.GetConsoleMode(handle, ctypes.byref(mode)))
    except Exception:
        return False


_ENTER = ("\r", "\n")
_BACKSPACE = "\b"
_CTRL_C = "\x03"
_CTRL_Z = "\x1a"
_SPECIAL_PREFIX = ("\x00", "\xe0")  # arrow/function keys arrive as two reads


def _read_masked_windows(prompt: str) -> str:
    import msvcrt

    sys.stdout.write(prompt)
    sys.stdout.flush()
    chars: list[str] = []
    while True:
        ch = msvcrt.getwch()
        if ch in _ENTER:
            break
        if ch == _CTRL_C:
            raise KeyboardInterrupt
        if ch == _CTRL_Z:
            raise EOFError
        if ch in _SPECIAL_PREFIX:
            msvcrt.getwch()  # discard the scan code that follows
            continue
        if ch == _BACKSPACE:
            if chars:
                chars.pop()
                sys.stdout.write("\b \b")
                sys.stdout.flush()
            continue
        chars.append(ch)
        sys.stdout.write("*")
        sys.stdout.flush()
    sys.stdout.write("\n")
    sys.stdout.flush()
    return "".join(chars)


def _read_masked_posix(prompt: str) -> str:
    import termios

    fd = sys.stdin.fileno()
    saved = termios.tcgetattr(fd)
    try:
        quiet = termios.tcgetattr(fd)
        quiet[3] &= ~termios.ECHO  # lflags
        termios.tcsetattr(fd, termios.TCSADRAIN, quiet)
        sys.stdout.write(prompt)
        sys.stdout.flush()
        line = sys.stdin.readline()
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, saved)
    sys.stdout.write("\n")
    sys.stdout.flush()
    if not line:
        raise EOFError
    return line.rstrip("\r\n")


def read_secret(prompt: str) -> str:
    """Read one line, hiding it where the terminal allows and always working.

    This deliberately does not use ``getpass``: see ``can_hide_input``
    for why that hangs on Windows outside a real console.  Where the keystrokes
    can be intercepted they are echoed as asterisks -- input that leaves no mark
    on screen reads as a frozen program, which is the complaint getpass invites.
    Everywhere else the line is read from stdin in the clear, which every
    terminal and every pipe can feed.
    """
    if can_hide_input():
        try:
            if os.name == "nt":
                return _read_masked_windows(prompt)
            return _read_masked_posix(prompt)
        except (OSError, ImportError, ValueError):
            pass  # fall through to a plain read rather than stranding the user

    sys.stdout.write(prompt)
    sys.stdout.flush()
    line = sys.stdin.readline()
    if not line:
        raise EOFError
    return line.rstrip("\r\n")


def status_line(code: int, phrase_text: str, detail: str) -> None:
    """One consistent line per server reply -- the thing the marker reads."""
    if 200 <= code < 300:
        colour = "green"
    elif code < 500:
        colour = "yellow"
    else:
        colour = "red"
    tag = paint(f"{code} {phrase_text}", colour, "bold")
    print(f"    {tag}  {paint(detail, 'grey')}")


# --------------------------------------------------------------------- units


def human_bytes(count: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(count) < 1024 or unit == "TB":
            return f"{count:.0f} {unit}" if unit == "B" else f"{count:.1f} {unit}"
        count /= 1024
    return f"{count:.1f} TB"


def human_rate(bytes_per_second: float) -> str:
    return human_bytes(bytes_per_second) + "/s"


def human_time(seconds: float) -> str:
    if seconds < 0 or seconds != seconds or seconds == float("inf"):
        return "--:--"
    seconds = int(seconds)
    if seconds >= 3600:
        return f"{seconds // 3600}h{(seconds % 3600) // 60:02d}m"
    return f"{seconds // 60:02d}:{seconds % 60:02d}"


def stamp() -> str:
    return datetime.now().strftime("%H:%M:%S")


# ------------------------------------------------------------------ progress


class Progress:
    """A single-line progress bar with rate and ETA.

    Falls back to periodic percentage lines when stdout is not a terminal, so
    piping to a file or a test harness does not produce megabytes of carriage
    returns.
    """

    def __init__(self, label: str, total: int, *, quiet: bool = False):
        self.label = label
        self.total = max(total, 0)
        self.quiet = quiet or not sys.stdout.isatty()
        self.started = time.monotonic()
        self.done = 0
        self._last_draw = 0.0
        self._finished = False

    def update(self, done: int) -> None:
        self.done = done
        now = time.monotonic()
        if now - self._last_draw < 0.08 and done < self.total:
            return
        self._last_draw = now
        if not self.quiet:
            self._draw(end="\r")

    def finish(self) -> None:
        if self._finished:
            return
        self._finished = True
        if self.quiet:
            elapsed = max(time.monotonic() - self.started, 1e-9)
            print(
                f"    {self.label}  {human_bytes(self.done)}"
                f"  in {elapsed:.2f}s  ({human_rate(self.done / elapsed)})"
            )
        else:
            self._draw(end="\n", final=True)

    def _draw(self, *, end: str, final: bool = False) -> None:
        elapsed = max(time.monotonic() - self.started, 1e-9)
        rate = self.done / elapsed
        width = min(shutil.get_terminal_size((80, 24)).columns, 78)

        if self.total:
            frac = min(self.done / self.total, 1.0)
        else:
            frac = 1.0 if final else 0.0

        # label + counters + bar all have to fit on one line
        counters = (
            f"{human_bytes(self.done):>9} / {human_bytes(self.total):<9}"
            f" {human_rate(rate):>10}"
        )
        if final:
            tail = f" {elapsed:5.2f}s"
        else:
            remaining = (self.total - self.done) / rate if rate > 0 else float("inf")
            tail = f" ETA {human_time(remaining)}"

        label = self.label[:22].ljust(22)
        bar_width = max(width - len(label) - len(counters) - len(tail) - 8, 6)
        filled = int(bar_width * frac)
        bar = "#" * filled + "." * (bar_width - filled)
        colour = "green" if final else "cyan"
        line = (
            f"    {label} [{paint(bar, colour)}] {int(frac * 100):3d}% "
            f"{counters}{tail}"
        )
        sys.stdout.write(line.ljust(width) + end)
        sys.stdout.flush()


# -------------------------------------------------------------------- tables


def table(headers: list[str], rows: list[list[str]], *, indent: str = "    ") -> None:
    if not rows:
        print(paint(f"{indent}(empty)", "grey"))
        return
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))
    head = indent + "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
    print(paint(head, "bold"))
    for row in rows:
        print(indent + "  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)))
