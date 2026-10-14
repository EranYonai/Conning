"""Which commands run without asking.

An allow rule is a short word list such as ("pytest",) or ("systemctl", "status"). A command's
"words" are its program name plus its non-flag arguments, so `pytest -x tests/smoke` has the
words ("pytest", "tests/smoke"). A rule matches when the command's words start with it.

"Always allow" remembers the first TWO words (decision D18): the danger lives in the verb,
so allowing `systemctl status` must never allow `systemctl stop`.

Wrappers that can run anything (`sh -c`, `python -c`, `sudo`, `env`, ...) are never matched
and never remembered, and a command string containing shell syntax always asks.
"""

import shlex
from pathlib import PureWindowsPath

WRAPPERS = frozenset(
    {
        "sh",
        "bash",
        "zsh",
        "dash",
        "ksh",
        "fish",
        "busybox",
        "python",
        "python3",
        "perl",
        "ruby",
        "node",
        "php",
        "pwsh",
        "powershell",
        "cmd",
        "sudo",
        "su",
        "doas",
        "env",
        "xargs",
        "nohup",
        "timeout",
        "nice",
        "setsid",
        "eval",
        "exec",
        "ssh",
        "scp",
        "rsync",
    }
)
SHELL_SYNTAX = (";", "|", "&", "`", "$(", ">", "<", "\n", "\r")


def program(word: str) -> str:
    """Program name without directory or .exe, lower-cased: '/usr/bin/Python3.exe' -> 'python3'."""
    name = PureWindowsPath(word).name.lower()
    return name[:-4] if name.endswith(".exe") else name


def split_command(cmd: str) -> list[str] | None:
    """Split a command string into argv, or None when it uses shell syntax and must always ask."""
    if any(token in cmd for token in SHELL_SYNTAX):
        return None
    try:
        argv = shlex.split(cmd)
    except ValueError:
        return None
    return argv or None


def words(argv: list[str]) -> tuple[str, ...]:
    if not argv:
        return ()
    return (program(argv[0]), *(a for a in argv[1:] if not a.startswith("-")))


def is_allowed(argv: list[str] | None, rules: tuple[tuple[str, ...], ...]) -> bool:
    if not argv or program(argv[0]) in WRAPPERS:
        return False
    w = words(argv)
    return any(w[: len(rule)] == tuple(r.lower() if i == 0 else r for i, r in enumerate(rule)) for rule in rules)


def remembered_rule(argv: list[str] | None) -> tuple[str, ...] | None:
    """The rule "always allow" stores for this command: its first two words, or None if never."""
    if not argv or program(argv[0]) in WRAPPERS:
        return None
    return words(argv)[:2]
