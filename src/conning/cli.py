"""The `conn` command line. Humans manage targets here; agents with only a shell may use it too.

Every agent-facing command prints exactly what the matching MCP tool returns.
"""

import argparse
import os
import sys

from conning import __version__, paths
from conning.output import DEFAULT_MAX_BYTES, MAX_BYTES_CEILING
from conning.targets import MODES, TargetFileError, listing, load_targets, select

PLANNED = "not implemented yet (planned for M1); see docs/design.md"


def _planned(args: argparse.Namespace) -> int:
    print(f"conn {args.command}: {PLANNED}", file=sys.stderr)
    return 2


def _targets(args: argparse.Namespace) -> int:
    try:
        targets = load_targets(paths.targets_file())
    except TargetFileError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(listing(select(targets, args.filter)))
    return 0


def _mcp(args: argparse.Namespace) -> int:
    if args.mcp_command in (None, "serve"):
        from conning.server import build_server

        build_server().run("stdio")
        return 0
    return _planned(argparse.Namespace(command=f"mcp {args.mcp_command}"))


def _help(args: argparse.Namespace) -> int:
    print(help_markdown() if args.markdown else build_parser().format_help())
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="conn",
        description="Conning: a control room for your agent's test machines.",
    )
    p.add_argument("--version", action="version", version=f"conning {__version__}")
    sub = p.add_subparsers(dest="command", metavar="<command>")

    def cmd(name: str, help: str, func=_planned, aliases=()) -> argparse.ArgumentParser:
        sp = sub.add_parser(name, help=help, description=help, aliases=list(aliases))
        sp.set_defaults(func=func)
        return sp

    # Agent-facing: same output as the MCP tools.
    sp = cmd("targets", "List targets: name, OS, shell, tags, mode. Never hosts or secrets.", _targets, ["ls"])
    sp.add_argument("filter", nargs="?", help="'tag:<tag>' or comma-separated names")
    sp.add_argument("--check", action="store_true", help="probe reachability in parallel")

    sp = cmd("run", "Run a command on one target, a list, or tag:<tag>. Exit code first.")
    sp.add_argument("target")
    sp.add_argument("--wait", type=int, default=30, help="seconds before returning a job id (0 = async)")
    sp.add_argument("--timeout", type=int, default=3600, help="kill the command after this many seconds")
    sp.add_argument("--cwd")
    sp.add_argument(
        "--max-bytes",
        type=int,
        default=DEFAULT_MAX_BYTES,
        help=f"output cap (default {DEFAULT_MAX_BYTES}, ceiling {MAX_BYTES_CEILING})",
    )
    sp.add_argument("--grep", help="keep only matching lines before capping")
    sp.add_argument("--json", action="store_true")
    sp.add_argument("argv", nargs=argparse.REMAINDER, help="-- then the command and its arguments")

    sp = cmd("read", "Page a job (new lines since last read), a saved output, or a remote file.")
    sp.add_argument("id", help="j:<job>, o:<output>, or <target>:<path>")
    sp.add_argument("--wait", type=int, default=0, help="long-poll up to this many seconds")
    sp.add_argument("--range", help="line range, e.g. 200-260 or -50 for the last 50")
    sp.add_argument("--grep")
    sp.add_argument("--signal", choices=["INT", "TERM", "KILL"])
    sp.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    sp.add_argument("--json", action="store_true")

    sp = cmd("transfer", "Copy files: local:<path> to <target>:<path>, or back. sha256 checked.")
    sp.add_argument("source")
    sp.add_argument("dest")

    # Target management. An agent may propose a target; it stays pending until you approve it.
    sp = cmd("add", "Add a target (an agent-added target stays pending until you approve it).")
    sp.add_argument("name")
    sp.add_argument("--host")
    sp.add_argument("--user")
    sp.add_argument("--port", type=int, default=22)
    sp.add_argument("--auth", choices=["ssh-agent", "key", "password"])
    sp.add_argument("--secret", help="reference only, e.g. op://Lab/vm/password or keychain:lab/vm")
    sp.add_argument("--mode", choices=MODES, default="ask")
    sp.add_argument("--tag", action="append", default=[])
    sp.add_argument("--retry", action="store_true", help="re-probe a target that failed to add")
    cmd("approve", "Approve a pending target: shows host, fingerprint and secret source first.").add_argument("name")
    cmd("import", "Import hosts from ~/.ssh/config (forwarding and unsafe options are dropped).").add_argument(
        "--match", default="*"
    )
    cmd("rm", "Remove a target.").add_argument("name")
    cmd("test", "Probe a target: reachability, OS, shell, pinned host key.").add_argument("name")
    sp = cmd("lease", "Grant a target full shell for a time box (default 15m, max 60m).")
    sp.add_argument("name")
    sp.add_argument("--minutes", type=int, default=15)

    # Human side.
    cmd("watch", "Live control room: every command on every target, and approval prompts.")
    cmd("doctor", "Check setup: agent permission rules, weak passwords, unpinned host keys.")
    sp = cmd("mcp", "Run the MCP server on stdio, or install it into an agent client.", _mcp)
    mcp_sub = sp.add_subparsers(dest="mcp_command", metavar="<serve|install>")
    mcp_sub.add_parser("serve", help="run the MCP server on stdio (the default)")
    mcp_sub.add_parser("install", help="add Conning to claude, codex or cursor").add_argument(
        "client", choices=["claude", "codex", "cursor"]
    )

    sp = cmd("help", "Show this help; --markdown prints the block cached in README.md.", _help)
    sp.add_argument("--markdown", action="store_true")
    return p


def help_markdown() -> str:
    """The CLI reference agents read from the README instead of calling --help (decision D10)."""
    columns = os.environ.get("COLUMNS")
    os.environ["COLUMNS"] = "100"  # stable wrapping, so the README copy can be checked in tests
    try:
        parser = build_parser()
        return _help_markdown(parser)
    finally:
        if columns is None:
            del os.environ["COLUMNS"]
        else:
            os.environ["COLUMNS"] = columns


def _help_markdown(parser: argparse.ArgumentParser) -> str:
    sub = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
    out = ["```"]
    for action in sub._choices_actions:
        sp = sub.choices[action.dest]
        usage = sp.format_usage().strip().removeprefix("usage: ").replace(" [-h]", "")
        out += [usage, f"    {action.help}", ""]
    out[-1] = "```"
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 0
    return args.func(args)
