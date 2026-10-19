"""The `conn` command line. Humans manage targets here; agents with only a shell may use it too.

Every agent-facing command prints exactly what the matching MCP tool returns.
"""

import argparse
import functools
import os
import sys

from conning import __version__, admin, complete, doctor, install, watch
from conning.output import DEFAULT_MAX_BYTES, MAX_BYTES_CEILING
from conning.secrets import SecretError
from conning.ssh import SSHError
from conning.targets import AUTHS, MODES, TargetFileError


def _core():
    from conning.core import Core

    return Core()


def _io():
    return admin.ConsoleIO()


def _emit(text: str) -> int:
    print(text)
    return 1 if text.startswith("error:") else 0


def _run(args: argparse.Namespace) -> int:
    if not args.argv:
        print(f"error: give the command after the target, e.g. conn run {args.target} uname -a")
        return 1
    if args.tty:
        return _run_live(args)
    common = dict(cwd=args.cwd, wait=args.wait, timeout=args.timeout, max_bytes=args.max_bytes, grep=args.grep)
    core, io = _core(), _io()
    core.notify = not io.tty  # a human at this terminal is asked right here, no pop-up needed
    command = {"cmd": " ".join(args.argv)} if args.shell else {"argv": args.argv}
    result = core.run(args.target, **command, **common)
    return admin.run_here(core, io, result, wait=args.wait, max_bytes=args.max_bytes, grep=args.grep)


def _write(text: str) -> None:
    sys.stdout.write(text)
    sys.stdout.flush()


def _run_live(args: argparse.Namespace) -> int:
    io = _io()
    if not io.tty:
        print("error: --tty needs a terminal; without one, leave it off")
        return 1
    command = {"cmd": " ".join(args.argv), "argv": None} if args.shell else {"cmd": None, "argv": args.argv}
    confirm = functools.partial(admin.confirm_live, io)
    result = _core().live(args.target, **command, cwd=args.cwd, confirm=confirm, write=_write)
    return _emit(result) if isinstance(result, str) else result


def _ssh(args: argparse.Namespace) -> int:
    if not _io().tty:
        print("error: conn ssh needs a terminal")
        return 1
    result = _core().shell(args.target)
    return _emit(result) if isinstance(result, str) else result


def _add(a: argparse.Namespace) -> int:
    return admin.add(
        _core(), _io(), a.name, host=a.host, user=a.user, port=a.port, auth=a.auth, secret=a.secret, key=a.key,
        os_name=a.os, mode=a.mode, tags=a.tag, like=a.like, jump=a.jump,
    )  # fmt: skip


def _watch(args: argparse.Namespace) -> int:
    try:
        return watch.watch(_core(), _io(), history=args.history, prompt=not args.no_prompt)
    except KeyboardInterrupt:
        return 0


def _mcp(args: argparse.Namespace) -> int:
    if args.mcp_command in (None, "serve"):
        from conning.server import build_server

        build_server(approve_in_client=args.approve_in_client).run("stdio")
        return 0
    return install.install(_io(), args.client, dry_run=args.dry_run)


HANDLERS = {
    "targets": lambda a: _emit(_core().targets(a.filter, a.check)),
    "run": _run,
    "read": lambda a: _emit(
        _core().read(a.id, wait=a.wait, range=a.range, grep=a.grep, signal=a.signal, max_bytes=a.max_bytes)
    ),
    "transfer": lambda a: _emit(_core().transfer(a.source, a.dest)),
    "ssh": _ssh,
    "targets add": _add,
    "targets import": lambda a: admin.import_ssh_config(_io(), a.match),
    "targets test": lambda a: admin.test(_core(), _io(), a.name),
    "targets mode": lambda a: admin.set_mode(_io(), a.target, a.mode),
    "targets rename": lambda a: admin.rename(_io(), a.old, a.new),
    "targets rm": lambda a: admin.remove(_io(), a.name),
    "approve": lambda a: admin.approve(_core(), _io(), a.what, always=a.always),
    "allow": lambda a: admin.allow(_io(), a.target, a.words),
    "deny": lambda a: admin.deny(_io(), a.target, a.words),
    "watch": _watch,
    "doctor": lambda a: doctor.doctor(_io()),
    "mcp": _mcp,
    "completion": lambda a: (
        complete.install() if a.shell == "install" else print(complete.SHELLS[a.shell], end="") or 0
    ),
    "help": lambda a: print(help_markdown() if a.markdown else build_parser().format_help()) or 0,
}


class Parser(argparse.ArgumentParser):
    """The top-level parser: `conn -h` lists the commands in sections, not in one argparse list."""

    sections: dict[str, list[tuple[str, argparse.ArgumentParser, str]]]

    def format_help(self) -> str:
        width = max(len(name) for rows in self.sections.values() for name, _, _ in rows)
        out = [self.format_usage(), self.description or "", ""]
        for title, rows in self.sections.items():
            out += [f"{title}:", *(f"  {name:<{width}}  {help}" for name, _, help in rows), ""]
        out.append("conn <command> -h shows a command's options; --version prints the version.")
        return "\n".join(out) + "\n"


TARGET_VERBS = ("add", "import", "test", "mode", "rename", "rm")


def build_parser() -> Parser:
    p = Parser(prog="conn", description="Conning: a light, local SSH controller for humans and agents.")
    p.add_argument("--version", action="version", version=f"conning {__version__}")
    sub = p.add_subparsers(dest="command", metavar="<command>", parser_class=argparse.ArgumentParser)
    p.sections = {}
    section = ""

    def cmd(name: str, help: str, under=sub) -> argparse.ArgumentParser:
        full = f"targets {name}" if under is not sub else name
        sp = under.add_parser(name, prog=f"conn {full}", help=help, description=help)
        sp.set_defaults(func=HANDLERS[full])
        p.sections.setdefault(section, []).append((full, sp, help))
        return sp

    section = "Agent commands (same output as the MCP tools)"
    sp = sub.add_parser(
        "targets",
        usage="conn targets [filter] [--check]\n       conn targets <verb> ...",
        description="List targets (filter: 'tag:<tag>' or comma-separated names), or manage them with a verb.",
    )
    verbs = sp.add_subparsers(dest="verb", metavar="<verb>")
    # `conn targets [filter]` is `conn targets ls`; main() inserts the hidden `ls` (no help, so unlisted).
    sp = verbs.add_parser("ls", prog="conn targets", description="List targets. Never secrets.")
    sp.set_defaults(func=HANDLERS["targets"])
    p.sections[section] = [("targets", sp, "List targets: name, OS, shell, host, user, tags, mode. Never secrets.")]
    sp.add_argument("filter", nargs="?", help="'tag:<tag>' or comma-separated names")
    sp.add_argument("--check", action="store_true", help="probe reachability in parallel")

    sp = cmd("run", "Run a command on one target, a list, or tag:<tag>. Exit code first.")
    sp.add_argument("target")
    sp.add_argument("--wait", type=int, default=30, help="seconds before returning a job id (0 = async)")
    sp.add_argument("--timeout", type=int, default=3600, help="kill the command after this many seconds")
    sp.add_argument("--cwd")
    sp.add_argument("--shell", action="store_true", help="send the words as one shell string (pipes etc. always ask)")
    sp.add_argument("-t", "--tty", action="store_true", help="for a human: live in a terminal (spinners, prompts)")
    sp.add_argument(
        "--max-bytes",
        type=int,
        default=DEFAULT_MAX_BYTES,
        help=f"output cap (default {DEFAULT_MAX_BYTES}, ceiling {MAX_BYTES_CEILING})",
    )
    sp.add_argument("--grep", help="keep only matching lines before capping")
    sp.add_argument("argv", nargs="*", help="the command and its arguments (conn's own options go before the target)")

    sp = cmd("read", "Page a job (new lines only), a saved output, an approval, or a remote file.")
    sp.add_argument("id", help="j:<job>, o:<output>, a:<approval>, or <target>:<path>")
    sp.add_argument("--wait", type=int, default=0, help="long-poll up to this many seconds")
    sp.add_argument("--range", help="line range, e.g. 200-260 or -50 for the last 50")
    sp.add_argument("--grep")
    sp.add_argument("--signal", choices=["INT", "TERM", "KILL"])
    sp.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)

    sp = cmd("transfer", "Copy files: local:<path> to <target>:<path>, or back. sha256 checked.")
    sp.add_argument("source")
    sp.add_argument("dest")

    section = "At a terminal"
    sp = cmd("ssh", "Human only: an interactive shell on a target, with its login, key, port and jump hosts.")
    sp.add_argument("target")

    section = "Targets (conn targets <verb>)"
    sp = cmd("add", "Add a target. Without a terminal it is saved as pending until a human approves it.", verbs)
    sp.add_argument("name")
    sp.add_argument("--host")
    sp.add_argument("--user")
    sp.add_argument("--like", metavar="TARGET", help="same machine as TARGET (host, port, OS, tags); pick --user")
    sp.add_argument("--port", type=int, help="default 22")
    sp.add_argument("--jump", metavar="TARGET", help="reach it through TARGET, a jump host (bastion)")
    sp.add_argument("--auth", choices=AUTHS)
    sp.add_argument("--secret", help="reference only: keychain:<service>/<account>, op://..., env:<NAME>")
    sp.add_argument("--key", help="private key file, for --auth key")
    sp.add_argument("--os", choices=["linux", "windows", "darwin"])
    sp.add_argument("--mode", choices=MODES, default="ask")
    sp.add_argument("--tag", action="append", default=[])
    sp = cmd("import", "Import hosts from ~/.ssh/config as pending targets (unsafe options dropped).", verbs)
    sp.add_argument("--match", default="*")
    cmd("test", "Probe a target: reachability, OS, shell, pinned host key.", verbs).add_argument("name")
    sp = cmd("mode", "Show or set ask or auto; auto runs anything without asking and needs a human.", verbs)
    sp.add_argument("target", help="a name, a comma list, or tag:<tag>")
    sp.add_argument("mode", nargs="?", choices=MODES)
    sp = cmd("rename", "Human only: rename a target; its host keys, password and pending work follow.", verbs)
    sp.add_argument("old")
    sp.add_argument("new")
    cmd("rm", "Remove a target and its pinned host key.", verbs).add_argument("name")

    section = "Trust"
    sp = cmd("approve", "Human only: make a target live, or allow a pending command a:<id>.")
    sp.add_argument("what", help="<target> or a:<id>")
    sp.add_argument("--always", action="store_true", help="for a:<id>: remember the command's first two words")
    sp = cmd("allow", "Human only: let a command run without asking (no words: list the rules).")
    sp.add_argument("target", help="a name, a comma list, or tag:<tag>")
    sp.add_argument("words", nargs="*", help="the command's leading words, e.g. systemctl status")
    sp = cmd("deny", "Remove an allow rule, so the command asks again (no terminal needed).")
    sp.add_argument("target", help="a name, a comma list, or tag:<tag>")
    sp.add_argument("words", nargs="+")

    section = "This machine"
    sp = cmd("watch", "Live control room: every command on every target, job output, approval prompts.")
    sp.add_argument("--history", type=int, default=10, help="show this many past events first")
    sp.add_argument("--no-prompt", action="store_true", help="show activity only; never ask")
    cmd("doctor", "Check this machine's setup: config and state dirs, ssh, keychain, targets.")
    sp = cmd("mcp", "Run the MCP server on stdio, or install it into an agent client.")
    sp.add_argument(
        "--approve-in-client",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="ask the human in the agent client (MCP elicitation) when a command needs approval",
    )
    mcp_sub = sp.add_subparsers(dest="mcp_command", metavar="<serve|install>")
    mcp_sub.add_parser("serve", help="run the MCP server on stdio (the default)")
    sp = mcp_sub.add_parser("install", help="add Conning and its skill to an agent client, and deny it raw ssh/scp")
    sp.add_argument("client", choices=list(install.PLANNERS))
    sp.add_argument("--dry-run", action="store_true", help="show what would change")

    sp = cmd("completion", "Tab completion that reads the target; conn completion install turns it on in your shell.")
    sp.add_argument("shell", choices=[*complete.SHELLS, "install"], help="install: add it to your shell's rc file")

    sp = cmd("help", "Show this help; --markdown prints the block cached in README.md.")
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


def _help_markdown(parser: Parser) -> str:
    out = []
    for title, rows in parser.sections.items():
        out += [f"# {title}", ""]
        for _, sp, help in rows:
            usage = sp.format_usage().strip().removeprefix("usage: ").replace(" [-h]", "")
            out += [usage, f"    {help}", ""]
    return "```\n" + "\n".join(out).strip() + "\n```"


RUN_VALUE_OPTIONS = ("--wait", "--timeout", "--cwd", "--max-bytes", "--grep")
RUN_FLAGS = ("--shell", "-t", "--tty")


def _run_options(argv: list[str], i: int) -> int:
    """Skip conn's own `run` options starting at argv[i]; return the index of the first other word."""
    while i < len(argv):
        word = argv[i]
        if word in RUN_VALUE_OPTIONS:
            i += 2
        elif word in RUN_FLAGS or word.split("=", 1)[0] in RUN_VALUE_OPTIONS:
            i += 1
        else:
            break
    return i


def _split_remote_command(argv: list[str]) -> tuple[list[str], list[str] | None]:
    """Cut off the remote command so argparse never sees its flags.

    `conn run [options] <target> [options] <command...>`: conn's own options may sit on either side of
    the target; the first other word starts the remote command, and everything from there on is passed
    through, flags included, so `conn run lab uname -a` works without `--`. An explicit `--` is honoured
    too (and needed on Python 3.11, whose argparse mishandles `--` before a subcommand's positionals).
    """
    if "--" in argv:
        cut = argv.index("--")
        return argv[:cut], argv[cut + 1 :]
    if not argv or argv[0] != "run":
        return argv, None
    target = _run_options(argv, 1)
    if target >= len(argv) or argv[target].startswith("-"):
        return argv, None  # no target (or -h): let argparse report it
    command = _run_options(argv, target + 1)
    return argv[:command], argv[command:]


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ["__complete"]:  # called by the completion script on every Tab; not in help
        return complete.main(argv[1:])
    parser = build_parser()
    if argv[:1] == ["targets"] and not set(argv[1:2]) & {*TARGET_VERBS, "ls", "-h", "--help"}:
        argv.insert(1, "ls")  # `conn targets [filter] [--check]` lists
    argv, rest = _split_remote_command(argv)
    args = parser.parse_args(argv)
    if rest is not None:
        if getattr(args, "command", None) != "run":
            parser.error("'--' is only used with conn run")
        args.argv = [*args.argv, *rest]
    if not getattr(args, "func", None):
        parser.print_help()
        return 0
    try:
        return args.func(args)
    except (OSError, TargetFileError, SecretError, SSHError) as e:  # one clear line, never a traceback
        print(f"error: {e}")
        return 1
    except KeyboardInterrupt:  # jobs on targets are detached and keep running; nothing here to clean up
        print("interrupted", file=sys.stderr, flush=True)
        sys.stdout.flush()
        os._exit(130)  # don't wait for worker threads still in a call
