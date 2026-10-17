"""Tab completion for `conn` in bash, zsh and fish (D53).

`conn completion <shell>` prints a script for the shell's rc file. On every Tab it calls
`conn __complete <words...> <current word>`, which prints one candidate per line.

After `conn run <target>`, candidates come from the target itself in one ssh call on its shared
connection: the next word of matching commands from Conning's own log and the target's shell history,
then command names (first word) or file names. Only live targets that run the read-only list (or have
`auto` mode) are asked, because a listing is what `ls` shows. Completion never asks for approval and never
writes to the audit log. History lines that look like they carry a secret are dropped; that is a
heuristic, not a guarantee, so a target can turn history off with `history = false`.
"""

import re
import shlex

from conning import audit, paths
from conning.targets import load_targets

SHELLS = {
    "bash": """_conn() {
    local -a words=("${COMP_WORDS[@]:1:COMP_CWORD}")  # sliced before IFS changes: bash 3.2 (macOS) joins it
    local IFS=$'\n' opts=$-
    set -f  # no glob on the candidates; bash 3.2 has no mapfile
    COMPREPLY=($(conn __complete "${words[@]}" 2>/dev/null))
    [[ $opts == *f* ]] || set +f
    [[ ${#COMPREPLY[@]} == 1 && ${COMPREPLY[0]} == */ ]] && type compopt &>/dev/null && compopt -o nospace
}
complete -F _conn conn
""",
    "zsh": """_conn() {
    local -a c
    c=("${(@f)$(conn __complete "${(@)words[2,CURRENT]}" 2>/dev/null)}")
    compadd -- ${c:#*/}
    compadd -S '' -- ${(M)c:#*/}
}
(( $+functions[compdef] )) || { autoload -Uz compinit && compinit; }  # works before or without a framework
compdef _conn conn
""",
    "fish": "complete -c conn -f -a '(conn __complete (commandline -opc)[2..-1] (commandline -ct) 2>/dev/null)'\n",
}
TARGET_FIRST = {"run", "test", "rm", "rename", "allow", "deny", "approve", "targets", "ls"}
SECRETISH = re.compile(r"pass(wd|word)|pw=|token|secret|api.?key|authori[sz]ation|bearer|://[^/\s:@]+:[^/\s@]+@", re.I)
HISTORY_LINES = 500
TIMEOUT = 5
MARK = "--conning-live--"


def remote_script(typed: list[str], cur: str, history: bool) -> str:
    """One POSIX script: matching history lines, a marker, then commands or files starting with `cur`."""
    first = typed[0] if typed else cur
    hist = (
        f'for f in ~/.bash_history ~/.zsh_history; do [ -r "$f" ] && tail -n 5000 "$f"; done 2>/dev/null'
        f" | sed 's/^: [0-9]*:[0-9]*;//' | grep -F -- {shlex.quote(first)} | tail -n {HISTORY_LINES}\n"
        if history
        else ""
    )
    if typed:
        live = (
            "b=''; case $p in '~/'*) b='~/'; p=${p#??}; cd ;; esac\n"
            """for f in "$p"*; do [ -e "$f" ] || continue; [ -d "$f" ] && f="$f/"; printf '%s\\n' "$b$f"; done\n"""
        )
    else:
        live = (
            """IFS=:; for d in $PATH; do for f in "$d/$p"*; do [ -x "$f" ] && printf '%s\\n' "${f##*/}"; done; done\n"""
        )
    return f"p={shlex.quote(cur)}\n{hist}echo {MARK}\n{live}exit 0\n"


def _next_words(lines: list[str], typed: list[str], cur: str) -> list[str]:
    """The word after `typed` in each line that starts with it, newest line first."""
    out = []
    for line in reversed(lines):
        if SECRETISH.search(line):
            continue
        try:
            words = shlex.split(line)
        except ValueError:
            words = line.split()
        if len(words) > len(typed) and words[: len(typed)] == typed and words[len(typed)].startswith(cur):
            out.append(words[len(typed)])
    return out


def remote(name: str, typed: list[str], cur: str, transport=None) -> list[str]:
    t = load_targets(paths.targets_file()).get(name)
    if t is None or t.status != "active" or not (t.safe or t.mode == "auto"):
        return []
    logged = [e["command"] for e in audit.read_from(0)[0] if e.get("event") == "run" and e.get("target") == name]
    found = []
    if t.os != "windows":
        from conning.secrets import SecretError
        from conning.ssh import SSHError
        from conning.transport import SSHTransport

        transport = transport or SSHTransport()
        try:
            rc, out = transport.exec(t, "sh -s", stdin=remote_script(typed, cur, t.history).encode(), timeout=TIMEOUT)
        except (SSHError, SecretError, OSError):
            rc, out = 1, b""
        if rc == 0:
            history, _, live = out.decode(errors="replace").partition(MARK + "\n")
            found = _next_words(history.splitlines(), typed, cur) + live.splitlines()
    return list(dict.fromkeys(_next_words(logged, typed, cur) + found))


def complete(words: list[str], transport=None) -> list[str]:
    """Candidates for the last word, given the words before it (without `conn`)."""
    from conning.cli import _run_options, build_parser

    *before, cur = words or [""]
    if not before:
        sub = next(a for a in build_parser()._actions if hasattr(a, "choices") and a.choices)
        return [c for c in sub.choices if c.startswith(cur) and not c.startswith("_")]
    command = before[0]
    if command == "run":
        at = _run_options(before, 1)
        if at < len(before):
            return remote(before[at], before[_run_options(before, at + 1) :], cur, transport)
    elif command not in TARGET_FIRST or any(not w.startswith("-") for w in before[1:]):
        return []
    if cur.startswith("-"):
        return []
    return sorted(n for n in load_targets(paths.targets_file()) if n.startswith(cur))


def main(words: list[str]) -> int:
    """`conn __complete`: print candidates, and stay quiet on any error, because a Tab must never fail."""
    try:
        print("\n".join(complete(words)))
    except Exception:  # noqa: BLE001 - whatever went wrong, a Tab shows nothing
        pass
    return 0
