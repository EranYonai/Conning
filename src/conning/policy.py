"""Which commands run without asking.

An allow rule is a short word list such as ("pytest",) or ("systemctl", "status"). A command's
"words" are its program name plus its non-flag arguments, so `pytest -x tests/smoke` has the
words ("pytest", "tests/smoke"). A rule matches when the command's words start with it.

"Always allow" remembers the first TWO words (decision D18): the danger lives in the verb,
so allowing `systemctl status` must never allow `systemctl stop`.

Wrappers that can run anything (`sh -c`, `python -c`, `sudo`, `env`, ...) are never matched
and never remembered, and a command string containing shell syntax always asks.

Every target also allows a built-in list of read-only commands (D39), unless it sets
`safe = false`. Each has its own argument check, because a word prefix is not enough there:
`hostname` prints the name but `hostname x` sets it, and `ip addr` shows but `ip addr add` changes.
Commands that print file contents (`cat`, `head`, `tail`) are not on it; the `read` tool reads files.
"""

import shlex
from pathlib import PureWindowsPath

WRAPPERS = frozenset(
    "sh bash zsh dash ksh fish busybox python python3 perl ruby node php pwsh powershell cmd "
    "sudo su doas env xargs nohup timeout nice setsid eval exec ssh scp rsync".split()
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


def policy_argv(cmd: str | None, argv: list[str] | None) -> list[str] | None:
    """The argv that policy checks: `argv` as given, or `cmd` split (None when it uses shell syntax)."""
    return argv if argv is not None else split_command(cmd or "")


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


# --- the built-in read-only list ----------------------------------------------------------------


def _any(rest: list[str]) -> bool:
    return True


def _only_flags(*allowed: str):
    def check(rest: list[str]) -> bool:
        return all(a in allowed for a in rest)

    return check


def _without(*forbidden: str):
    def check(rest: list[str]) -> bool:
        return not any(a == f or a.startswith(f + "=") for a in rest for f in forbidden)

    return check


IP_OBJECTS = {"a", "addr", "address", "l", "link", "r", "route", "n", "neigh", "neighbour", "neighbor"}
IP_FLAGS = set("-4 -6 -br -brief -c -color -s -stats -d -details -o -oneline -j -json -p -pretty".split())


def _ip(rest: list[str]) -> bool:
    """`ip addr`, `ip -br link show`: only show/list, only display flags (`-batch` would run a file)."""
    flags = [a for a in rest if a.startswith("-")]
    plain = [a for a in rest if not a.startswith("-")]
    if any(f not in IP_FLAGS for f in flags) or not plain or plain[0] not in IP_OBJECTS:
        return False
    return len(plain) == 1 or plain[1] in ("show", "list", "ls")


SYSTEMCTL_READ = set("status show cat is-active is-enabled is-failed list-units list-unit-files list-timers".split())
SYSTEMCTL_FLAGS = set("--no-pager -l --full -a --all --plain --no-legend --user --value -q --quiet".split())
SYSTEMCTL_VALUE_FLAGS = ("-t", "--type", "--state", "-n", "--lines", "-o", "--output", "-p", "--property")


def _systemctl(rest: list[str]) -> bool:
    """Read verbs only, and no -H/--host or -M: those reach other machines."""
    plain = [a for a in rest if not a.startswith("-")]
    flags = [a for a in rest if a.startswith("-")]
    ok_flag = all(f in SYSTEMCTL_FLAGS or f.split("=")[0] in SYSTEMCTL_VALUE_FLAGS for f in flags)
    return ok_flag and bool(plain) and plain[0] in SYSTEMCTL_READ


SAFE: dict[str, object] = {
    # POSIX
    **dict.fromkeys("uname uptime df free id whoami ps ls pwd nproc lscpu lsblk".split(), _any),
    "hostname": _only_flags(
        *"-f --fqdn --long -s --short -d --domain -i --ip-address "
        "-I --all-ip-addresses -A --all-fqdns -a --alias".split()
    ),
    "ip": _ip,
    "systemctl": _systemctl,
    "journalctl": _without(
        *"--vacuum-size --vacuum-time --vacuum-files --rotate --flush --sync "
        "--relinquish-var --smart-relinquish-var --setup-keys --update-catalog".split()
    ),
    # Windows (PowerShell); names are matched lower-case
    "ipconfig": _only_flags("/all"),
    **dict.fromkeys("get-computerinfo get-process get-service get-netipaddress get-volume get-hotfix".split(), _any),
}


def is_safe(argv: list[str] | None) -> bool:
    """On the built-in read-only list. The program must be a bare name, found on the target's PATH:
    `/tmp/x/uname` could be anything the agent uploaded."""
    if not argv or "/" in argv[0] or "\\" in argv[0]:
        return False
    check = SAFE.get(program(argv[0]))
    return check is not None and check(argv[1:])
