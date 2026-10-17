"""`conn doctor`: check this machine's setup and say what to fix, one line per finding.

Written for the case that confused the first real user: an agent sandbox where the config dir is
read-only and the OS keychain is out of reach. Doctor names the problem and the way around it.
"""

import os
import shutil
from pathlib import Path

from conning import __version__, audit, paths, secrets, ssh
from conning.admin import IO
from conning.state import problems
from conning.targets import TargetFileError, load_targets


def _writable(directory: Path) -> bool:
    probe = directory
    while not probe.exists() and probe != probe.parent:
        probe = probe.parent
    return os.access(probe, os.W_OK)


def doctor(io: IO) -> int:
    failed = False

    def report(level: str, text: str) -> None:
        nonlocal failed
        failed = failed or level == "FAIL"
        io.say(f"{level:<5}{text}")

    report("ok", f"conning {__version__}")
    if secrets.in_container():
        report("ok", "running in a container: keep /conning on a volume, and approve from the host")
    config, state = paths.config_dir(), paths.state_dir()
    if _writable(config):
        report("ok", f"config {config}")
    else:
        report(
            "warn",
            f"config {config} is read-only here: commands still run, but add, approve, allow and rename "
            "must happen in a normal terminal (an agent sandbox usually looks like this)",
        )
    try:
        state.mkdir(parents=True, exist_ok=True)
        (state / ".doctor").write_text("ok")
        (state / ".doctor").unlink()
        report("ok", f"state {state}")
    except OSError as e:
        report("FAIL", f"state {state} is not writable ({e.strerror}); set CONNING_STATE to a writable folder")

    broken = audit.verify()
    if broken:
        report("warn", f"audit log {audit.log_file()} was edited or truncated at line {broken}")
    for tool in ("ssh", "scp", "ssh-keyscan"):
        if shutil.which(tool):
            report("ok", f"{tool} found")
        else:
            report("FAIL", f"{tool} not found; install the OpenSSH client")
    try:
        if ssh.control_dir() is None:
            report("warn", "SSH connection reuse is off here (no short private socket folder); each call reconnects")
    except ssh.SSHError as e:
        report("warn", f"SSH connection reuse is off: {e}")

    try:
        targets = load_targets(paths.targets_file())
    except TargetFileError as e:
        report("FAIL", str(e))
        return 1
    if not targets:
        report("warn", f"no targets in {paths.targets_file()} (add one with: conn add <name>)")
        return 1 if failed else 0
    report("ok", f"{len(targets)} target(s) in {paths.targets_file()}")

    refs = [t.secret for t in targets.values() if t.secret] + [
        ref for t in targets.values() for ref in t.inject.values()
    ]
    if any(r.startswith("keychain:") for r in refs):
        if secrets.in_container():
            report("FAIL", f"a secret uses keychain: but {secrets.NO_KEYCHAIN}")
        else:
            try:
                secrets._keyring().get_password(secrets.KEYCHAIN_SERVICE, "conning-doctor-probe")
                report("ok", "OS keychain reachable")
            except Exception as e:  # noqa: BLE001 - every keyring backend fails differently
                report(
                    "FAIL",
                    f"OS keychain not reachable here ({type(e).__name__}: {e}); run Conning outside the sandbox, "
                    "e.g. as the MCP server your agent client starts",
                )
    if any(r.startswith("op://") for r in refs) and not shutil.which("op"):
        report("FAIL", "a secret uses op:// but the 1Password CLI (op) is not installed")
    for ref in sorted({r for r in refs if r.startswith("env:")}):
        if os.environ.get(ref[4:]) is None:
            report("warn", f"secret {ref} is not set in this environment")

    pinned = (config / "known_hosts").read_text() if (config / "known_hosts").exists() else ""
    notes = problems()
    for t in targets.values():
        if t.status == "pending":
            why = f" ({notes[t.name]})" if t.name in notes else ""
            report("warn", f"{t.name} is pending{why}; a human runs: conn approve {t.name}")
        elif f"{ssh.host_key_alias(t.name)} " not in pinned:
            report("FAIL", f"{t.name} has no pinned host key; run: conn approve {t.name}")
        if t.mode == "auto":
            report("warn", f"{t.name} has mode=auto: the agent may run anything there without asking")
    return 1 if failed else 0
