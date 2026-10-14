"""The `conn` command line. Humans manage targets here; agents with only a shell may use it too.

Every agent-facing command prints exactly what the matching MCP tool returns.
"""

import argparse
import os
import sys

from conning import __version__
from conning.output import DEFAULT_MAX_BYTES, MAX_BYTES_CEILING
from conning.targets import AUTHS, MODES

PLANNED = "not implemented yet (planned for M2); see docs/design.md"


def _core():
    from conning.core import Core

    return Core()


def _io():
    from conning.admin import ConsoleIO

    return ConsoleIO()


def _emit(text: str) -> int:
    print(text)
    return 1 if text.startswith("error:") else 0


def _planned(args: argparse.Namespace) -> int:
    print(f"conn {args.command}: {PLANNED}", file=sys.stderr)
    return 2


def _targets(args: argparse.Namespace) -> int:
    return _emit(_core().targets(args.filter, args.check))


def _run(args: argparse.Namespace) -> int:
    argv = args.argv
    if not argv:
        print("error: give the command after --, e.g. conn run lab-lin1 -- uname -a")
        return 1
    common = dict(cwd=args.cwd, wait=args.wait, timeout=args.timeout, max_bytes=args.max_bytes, grep=args.grep)
    if args.shell:
        return _emit(_core().run(args.target, cmd=" ".join(argv), **common))
    return _emit(_core().run(args.target, argv=argv, **common))


def _read(args: argparse.Namespace) -> int:
    return _emit(
        _core().read(
            args.id, wait=args.wait, range=args.range, grep=args.grep, signal=args.signal, max_bytes=args.max_bytes
        )
    )


def _transfer(args: argparse.Namespace) -> int:
    return _emit(_core().transfer(args.source, args.dest))


def _add(args: argparse.Namespace) -> int:
    from conning import admin

    return admin.add(
        _core(),
        _io(),
        args.name,
        host=args.host,
        user=args.user,
        port=args.port,
        auth=args.auth,
        secret=args.secret,
        key=args.key,
        os_name=args.os,
        mode=args.mode,
        tags=args.tag,
        retry=args.retry,
    )


def _approve(args: argparse.Namespace) -> int:
    from conning import admin

    return admin.approve(_core(), _io(), args.what, always=args.always)


def _rm(args: argparse.Namespace) -> int:
    from conning import admin

    return admin.remove(_io(), args.name)


def _test(args: argparse.Namespace) -> int:
    from conning import admin

    return admin.test(_core(), _io(), args.name)


def _lease(args: argparse.Namespace) -> int:
    from conning import admin

    return admin.lease(_io(), args.name, args.minutes)


def _import(args: argparse.Namespace) -> int:
    from conning import admin

    return admin.import_ssh_config(_io(), args.match)


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
    p = argparse.ArgumentParser(prog="conn", description="Conning: a control room for your agent's test machines.")
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

    sp = cmd("run", "Run a command on one target, a list, or tag:<tag>. Exit code first.", _run)
    sp.add_argument("target")
    sp.add_argument("--wait", type=int, default=30, help="seconds before returning a job id (0 = async)")
    sp.add_argument("--timeout", type=int, default=3600, help="kill the command after this many seconds")
    sp.add_argument("--cwd")
    sp.add_argument("--shell", action="store_true", help="send the words as one shell string (pipes etc. always ask)")
    sp.add_argument(
        "--max-bytes",
        type=int,
        default=DEFAULT_MAX_BYTES,
        help=f"output cap (default {DEFAULT_MAX_BYTES}, ceiling {MAX_BYTES_CEILING})",
    )
    sp.add_argument("--grep", help="keep only matching lines before capping")
    sp.add_argument("argv", nargs="*", help="-- then the command and its arguments")

    sp = cmd("read", "Page a job (new lines only), a saved output, an approval, or a remote file.", _read)
    sp.add_argument("id", help="j:<job>, o:<output>, a:<approval>, or <target>:<path>")
    sp.add_argument("--wait", type=int, default=0, help="long-poll up to this many seconds")
    sp.add_argument("--range", help="line range, e.g. 200-260 or -50 for the last 50")
    sp.add_argument("--grep")
    sp.add_argument("--signal", choices=["INT", "TERM", "KILL"])
    sp.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)

    sp = cmd("transfer", "Copy files: local:<path> to <target>:<path>, or back. sha256 checked.", _transfer)
    sp.add_argument("source")
    sp.add_argument("dest")

    # Target management. Without a terminal (an agent), a new target is saved as pending.
    sp = cmd("add", "Add a target. Without a terminal it is saved as pending until a human approves it.", _add)
    sp.add_argument("name")
    sp.add_argument("--host")
    sp.add_argument("--user")
    sp.add_argument("--port", type=int, default=22)
    sp.add_argument("--auth", choices=AUTHS)
    sp.add_argument("--secret", help="reference only: keychain:<service>/<account>, op://..., env:<NAME>")
    sp.add_argument("--key", help="private key file, for --auth key")
    sp.add_argument("--os", choices=["linux", "windows", "darwin"])
    sp.add_argument("--mode", choices=MODES, default="ask")
    sp.add_argument("--tag", action="append", default=[])
    sp.add_argument("--retry", action="store_true", help="probe an existing target again")
    sp = cmd("approve", "Human only: make a pending target live, or allow a pending command a:<id>.", _approve)
    sp.add_argument("what", help="<target> or a:<id>")
    sp.add_argument("--always", action="store_true", help="for a:<id>: remember the command's first two words")
    sp = cmd("import", "Import hosts from ~/.ssh/config as pending targets (unsafe options dropped).", _import)
    sp.add_argument("--match", default="*")
    cmd("rm", "Remove a target and its pinned host key.", _rm).add_argument("name")
    cmd("test", "Probe a target: reachability, OS, shell, pinned host key.", _test).add_argument("name")
    sp = cmd("lease", "Human only: give a target a full shell for a time box (1-60 minutes).", _lease)
    sp.add_argument("name")
    sp.add_argument("--minutes", type=int, default=15)

    # Human side, M2.
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
