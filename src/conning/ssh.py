"""The OpenSSH connector.

Conning never reads your ~/.ssh/config at run time. For every call it generates a per-target config
that pins the host key (StrictHostKeyChecking yes, a known_hosts file of its own) and turns every
kind of forwarding off. Passwords are handed to ssh through an askpass helper and an environment
variable of the ssh process, never on a command line.
"""

import base64
import getpass
import hashlib
import os
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from conning import paths, secrets
from conning.targets import Target

ALIAS = "conning-target"
IS_WINDOWS_HOST = os.name == "nt"


class SSHError(RuntimeError):
    pass


def require_ssh() -> str:
    exe = shutil.which("ssh")
    if not exe:
        raise SSHError("OpenSSH client (ssh) not found on this machine")
    return exe


def host_key_alias(name: str) -> str:
    return f"conning-{name}"


SHORT_TMP = Path("/tmp")  # macOS's per-user temp dir (/var/folders/...) is too long for socket paths
SOCKET_PATH_MAX = 104  # sun_path on macOS and BSD (108 on Linux)
CONTROL_SUFFIX = 58  # "/" + the socket name (40 hex chars) + the 17-char temporary suffix ssh adds


def runtime_dir() -> Path:
    """A private, short dir for control sockets and the askpass helper."""
    uid = os.getuid() if hasattr(os, "getuid") else getpass.getuser()
    base = SHORT_TMP if not IS_WINDOWS_HOST and SHORT_TMP.is_dir() else Path(tempfile.gettempdir())
    d = base / f"conning-{uid}"
    d.mkdir(mode=0o700, exist_ok=True)
    if hasattr(os, "getuid"):  # /tmp is shared: refuse a dir someone else made or can write to
        st = d.lstat()
        if stat.S_ISLNK(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077:
            raise SSHError(f"{d} is not a private directory owned by you; remove it and retry")
    return d


def control_dir() -> Path | None:
    """Where connection-sharing sockets go, or None to run without connection reuse."""
    if IS_WINDOWS_HOST:
        return None
    d = runtime_dir()
    return d if len(str(d)) + CONTROL_SUFFIX <= SOCKET_PATH_MAX else None


def config_text(t: Target, known_hosts: Path, control_dir: Path | None) -> str:
    lines = [
        f"Host {ALIAS}",
        f"  HostName {t.host}",
        f"  Port {t.port}",
        f"  User {t.user}",
        f"  HostKeyAlias {host_key_alias(t.name)}",
        f'  UserKnownHostsFile "{known_hosts}"',
        "  GlobalKnownHostsFile " + ("NUL" if IS_WINDOWS_HOST else "/dev/null"),
        "  StrictHostKeyChecking yes",
        "  UpdateHostKeys no",
        "  ForwardAgent no",
        "  ForwardX11 no",
        "  ClearAllForwardings yes",
        "  PermitLocalCommand no",
        "  ConnectTimeout 10",
        "  ServerAliveInterval 15",
        "  ServerAliveCountMax 3",
        "  LogLevel ERROR",
    ]
    if t.auth == "password":
        lines += [
            "  PreferredAuthentications password,keyboard-interactive",
            "  PubkeyAuthentication no",
            "  NumberOfPasswordPrompts 1",
        ]
    else:
        lines += ["  PreferredAuthentications publickey", "  BatchMode yes"]
        if t.auth == "key" and t.key:
            lines += [f'  IdentityFile "{Path(t.key).expanduser()}"', "  IdentitiesOnly yes"]
    if control_dir is not None:
        # One shared connection per target and setup, not per host and user (ssh's %C): a target
        # with another name, key, password or known_hosts must log in itself, not ride another's.
        socket_name = hashlib.sha1("\n".join(lines).encode()).hexdigest()  # 40 chars, like %C
        lines += ["  ControlMaster auto", f'  ControlPath "{control_dir}/{socket_name}"', "  ControlPersist 600"]
    return "\n".join(lines) + "\n"


@dataclass
class Connection:
    argv: list[str]  # ssh -F <conf> ... conning-target
    env: dict[str, str]
    secrets: list[str]  # resolved values used by this connection, for redaction


def connect(t: Target) -> Connection:
    """Prepare (not open) a connection: write the generated config and resolve the password if any."""
    ssh = require_ssh()
    known_hosts = paths.config_dir() / "known_hosts"  # read only here; written when a human pins keys
    generated = paths.state_dir() / "ssh"
    generated.mkdir(parents=True, exist_ok=True)
    control = control_dir()
    conf = generated / f"{t.name}.conf"
    conf.write_text(config_text(t, known_hosts, control), encoding="utf-8")
    env = dict(os.environ)
    used: list[str] = []
    if t.auth == "password":
        if not t.secret:
            raise SSHError(f"{t.name}: password auth without a secret reference")
        password = secrets.resolve(t.secret)
        used.append(password)
        env.update(
            SSH_ASKPASS=str(_askpass_helper()),
            SSH_ASKPASS_REQUIRE="force",
            DISPLAY=env.get("DISPLAY", ":0"),
            CONNING_ASKPASS_VALUE=password,
        )
    return Connection(argv=[ssh, "-F", str(conf), "-T", ALIAS], env=env, secrets=used)


def _askpass_helper() -> Path:
    """A tiny program ssh runs to get the password: it prints CONNING_ASKPASS_VALUE and exits."""
    d = runtime_dir()
    if IS_WINDOWS_HOST:
        helper = d / "askpass.cmd"
        helper.write_text(f'@"{sys.executable}" -m conning.askpass\r\n', encoding="utf-8")
    else:
        helper = d / "askpass.sh"
        helper.write_text(f'#!/bin/sh\nexec "{sys.executable}" -m conning.askpass\n', encoding="utf-8")
        helper.chmod(0o700)
    return helper


def run(conn: Connection, remote_command: str, *, stdin: bytes | None = None, timeout: float = 60) -> tuple[int, bytes]:
    """Run one command over ssh. Returns (exit code, stdout+stderr). 255 means ssh itself failed."""
    try:
        done = subprocess.run(
            [*conn.argv, "--", remote_command],
            input=stdin if stdin is not None else b"",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=conn.env,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as e:
        return 124, (e.output or b"") + b"\n[conning: ssh call timed out]"
    return done.returncode, done.stdout


def explain_ssh_failure(output: bytes) -> str:
    text = output.decode(errors="replace")
    if "REMOTE HOST IDENTIFICATION HAS CHANGED" in text or "Host key verification failed" in text:
        return "host key does not match the pinned key (hard fail; a human must re-pin with conn approve)"
    if "Permission denied" in text:
        return "authentication failed (check the user and secret with conn test)"
    if "Connection refused" in text:
        return "connection refused (no SSH server listening on that port)"
    if "timed out" in text or "No route to host" in text:
        return "host unreachable"
    return text.strip().splitlines()[-1] if text.strip() else "ssh failed"


# --- host keys -------------------------------------------------------------------------------


def scan_host_keys(host: str, port: int) -> list[tuple[str, str, str]]:
    """Return [(key_type, fingerprint, key_base64)] as offered by the server right now."""
    keyscan = shutil.which("ssh-keyscan")
    if not keyscan:
        raise SSHError("ssh-keyscan not found on this machine")
    done = subprocess.run([keyscan, "-p", str(port), "-T", "10", host], capture_output=True, text=True, timeout=30)
    keys = []
    for line in done.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3 and not line.startswith("#"):
            keys.append((parts[1], fingerprint(parts[2]), parts[2]))
    return keys


def fingerprint(key_b64: str) -> str:
    digest = hashlib.sha256(base64.b64decode(key_b64)).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


def pin_host_keys(name: str, keys: list[tuple[str, str, str]]) -> None:
    """Replace this target's entries in Conning's known_hosts with the given keys."""
    known_hosts = paths.config_dir() / "known_hosts"
    alias = host_key_alias(name)
    old = known_hosts.read_text().splitlines() if known_hosts.exists() else []
    kept = [line for line in old if line.split(" ", 1)[0] != alias]
    kept += [f"{alias} {key_type} {key}" for key_type, _, key in keys]
    known_hosts.parent.mkdir(parents=True, exist_ok=True)
    known_hosts.write_text("\n".join(kept) + "\n")


def rename_host_keys(old: str, new: str) -> None:
    """Pin the keys pinned for `old` under `new` instead (`conn rename`)."""
    known_hosts = paths.config_dir() / "known_hosts"
    if not known_hosts.exists():
        return
    alias, renamed = host_key_alias(old), host_key_alias(new)
    lines = known_hosts.read_text().splitlines()
    known_hosts.write_text(
        "\n".join(renamed + line[len(alias) :] if line.split(" ", 1)[0] == alias else line for line in lines) + "\n"
    )


def port_open(host: str, port: int, timeout: float = 3) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


WINDOWS_SSH_FIX = """\
{name}: no SSH server on {host}:{port}, and it answers on {ports}, so it looks like Windows.
Ask the user to run this on the VM, in an admin PowerShell, then retry with: conn add {name} --retry
  Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
  Start-Service sshd; Set-Service sshd -StartupType Automatic
Windows older than 10 1809 / Server 2019: install Win32-OpenSSH from its GitHub releases (MSI) instead."""


def no_ssh_hint(t: Target) -> str:
    windows_ports = [p for p in (3389, 5985, 5986) if port_open(t.host, p, timeout=2)]
    if windows_ports:
        return WINDOWS_SSH_FIX.format(name=t.name, host=t.host, port=t.port, ports=", ".join(map(str, windows_ports)))
    return f"{t.name}: nothing listens on {t.host}:{t.port}. Ask the user to start an SSH server on the target."
