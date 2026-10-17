"""D39: the built-in read-only commands run without asking, and nothing that changes a machine slips in."""

import pytest
from conftest import target, write_targets
from test_admin import FakeIO

from conning import admin, paths
from conning.policy import is_safe, split_command
from conning.targets import TargetFileError, dump_targets, load_targets


@pytest.mark.parametrize(
    "cmd",
    [
        "uname -a",
        "hostname",
        "hostname -I",
        "hostname --fqdn",
        "uptime",
        "df -h /",
        "free -m",
        "id",
        "whoami",
        "ps aux",
        "ls -la /var/log",
        "pwd",
        "nproc",
        "lscpu",
        "lsblk -f",
        "ip addr",
        "ip -br a",
        "ip -4 addr show dev eth0",
        "ip route list",
        "ip -j link show",
        "systemctl status sshd",
        "systemctl --no-pager -l status nginx",
        "systemctl list-units --type=service --state=failed",
        "systemctl is-active docker",
        "journalctl -u sshd -n 50 --no-pager",
        "journalctl --since today",
        "ipconfig",
        "ipconfig /all",
        "Get-ComputerInfo",
        "Get-Process -Name pwsh",
        "get-service",
        "Get-NetIPAddress",
        "Get-Volume",
        "Get-HotFix",
        "UNAME -a",  # program names are matched lower-case
        "whoami.exe",
    ],
)
def test_read_only_commands_are_safe(cmd):
    assert is_safe(split_command(cmd)), cmd


@pytest.mark.parametrize(
    "cmd",
    [
        "hostname evil",  # sets the host name
        "hostname -F /etc/x",
        "hostname -b x",
        "ip addr add 10.0.0.9/24 dev eth0",
        "ip route del default",
        "ip link set eth0 down",
        "ip -batch /tmp/cmds",  # runs a file of commands
        "ip -force addr",
        "ip",
        "ip tunnel",
        "systemctl stop sshd",
        "systemctl restart nginx",
        "systemctl -H other-host status sshd",  # reaches another machine
        "systemctl --host=other status sshd",
        "systemctl -M container status",
        "systemctl",
        "journalctl --vacuum-size=1M",
        "journalctl --rotate",
        "journalctl --flush",
        "ipconfig /release",
        "ipconfig /renew",
        "cat /etc/shadow",  # file readers are not on the list
        "head -n 5 /etc/passwd",
        "tail -f /var/log/syslog",
        "/tmp/evil/uname",  # a path could be anything the agent uploaded
        "./uname",
        "C:\\tmp\\whoami.exe",
        "sh -c uname",
        "sudo ls",
        "rm -rf /",
        "reboot",
    ],
)
def test_commands_that_change_things_are_not_safe(cmd):
    assert not is_safe(split_command(cmd)), cmd


def test_shell_syntax_paths_and_empty_are_not_safe():
    assert not is_safe(split_command("uname; reboot"))
    assert not is_safe(["C:\\tools\\whoami.exe"]) and not is_safe(["bin/ls"])
    assert not is_safe(None) and not is_safe([])


def test_safe_key_is_fail_closed_and_round_trips(home):
    write_targets(target("lab"), target("prod", safe=False))
    loaded = load_targets(paths.targets_file())
    assert loaded["lab"].safe is True and loaded["prod"].safe is False
    text = dump_targets(loaded)
    assert text.count("safe = false") == 1  # the default is not written
    paths.targets_file().write_text('[lab]\nhost = "h"\nuser = "u"\nsafe = "yes"\n')
    with pytest.raises(TargetFileError, match="'safe' must be true or false"):
        load_targets(paths.targets_file())


def test_engine_runs_safe_commands_without_asking(core, transport):
    write_targets(target("lab"), target("prod", safe=False), target("free", mode="auto"))
    transport.canned["sh -s"] = (0, b"4242\n")  # job start answers with a pid
    assert core.would_ask("lab,prod,free", None, ["uname", "-a"]) == ["prod"]
    assert core.would_ask("lab", None, ["hostname", "evil"]) == ["lab"]
    assert core._decide(load_targets(paths.targets_file())["free"], ["reboot"]) == "run"  # auto runs anything


def test_allow_lists_a_target_without_the_built_in_list(home):
    write_targets(target("prod", safe=False))
    io = FakeIO(tty=False)
    assert admin.allow(io, "prod", []) == 0
    assert io.said == ["prod: no built-in list (safe = false); rules: (none)"]
