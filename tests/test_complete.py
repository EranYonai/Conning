"""D50: Tab completion from the target: history and live listings, gated like `ls`, never audited."""

import subprocess

import pytest
from conftest import needs_sh, target, write_targets

from conning import audit, cli, complete
from conning.state import grant_lease


@pytest.fixture
def lab(home, transport, monkeypatch):
    monkeypatch.chdir(transport.remote_home)  # the local sh stands in for the target, in its home
    write_targets(target("lab"), target("lab2"), target("win", os="windows"))
    (transport.remote_home / ".bash_history").write_text(
        "systemctl status nginx\nsystemctl restart nginx\nmysql --password=hunter2 db\nls\n"
    )
    (transport.remote_home / ".zsh_history").write_text(": 1700000000:0;systemctl reload sshd\n")
    (transport.remote_home / "logs").mkdir()
    (transport.remote_home / "log.txt").write_text("")
    return transport


def test_subcommands_and_target_names(lab):
    assert complete.complete(["r"]) == ["run", "read", "rm", "rename"]
    assert "__complete" not in complete.complete([""])
    assert complete.complete(["run", "l"]) == ["lab", "lab2"]
    assert complete.complete(["run", "--wait", "5", "lab"]) == ["lab", "lab2"]
    assert complete.complete(["test", ""]) == ["lab", "lab2", "win"]
    assert complete.complete(["test", "-"]) == []
    assert complete.complete(["rename", "lab", ""]) == []  # only the first word is a target
    assert complete.complete(["doctor", ""]) == []


@needs_sh
def test_next_word_from_history_newest_first_and_no_secrets(lab):
    assert complete.complete(["run", "lab", "systemctl", ""], lab)[:3] == ["reload", "restart", "status"]
    assert complete.complete(["run", "lab", "systemctl", "restart", ""], lab) == ["nginx", "log.txt", "logs/"]
    assert "--password=hunter2" not in "\n".join(complete.complete(["run", "lab", "mysql", ""], lab))
    assert complete.complete(["run", "lab", "--wait", "5", "systemctl", "rel"], lab) == ["reload"]


@needs_sh
def test_conning_log_counts_as_history(lab):
    audit.record("run", target="lab", command="journalctl -u nginx")
    audit.record("run", target="lab2", command="journalctl -u other")
    assert complete.complete(["run", "lab", "journalctl", "-u", "n"], lab) == ["nginx"]


@needs_sh
def test_live_commands_and_files(lab):
    assert "sh" in complete.complete(["run", "lab", "s"], lab)
    assert complete.complete(["run", "lab", "ls", "~/lo"], lab) == ["~/log.txt", "~/logs/"]
    assert complete.complete(["run", "lab", "ls", "lo"], lab) == ["log.txt", "logs/"]


@needs_sh
def test_history_can_be_turned_off(lab):
    write_targets(target("lab", history=False))
    assert complete.complete(["run", "lab", "systemctl", ""], lab) == ["log.txt", "logs/"]


def test_gated_like_ls_and_never_audited(lab):
    write_targets(target("p", status="pending"), target("off", safe=False), target("win", os="windows"))
    assert complete.complete(["run", "p", ""], lab) == []
    assert complete.complete(["run", "off", ""], lab) == []
    assert complete.complete(["run", "win", ""], lab) == []
    assert complete.complete(["run", "nope", ""], lab) == []
    assert lab.calls == []
    grant_lease("off", 10)
    lab.canned["sh -s"] = (0, b"x y\nx 'z\n--conning-live--\nyes\n")  # a stray quote still splits
    assert complete.complete(["run", "off", "x", ""], lab) == ["'z", "y", "yes"]
    assert complete.complete(["run", "off", ""], lab) == ["x", "yes"]
    assert audit.read_from(0)[0] == []


def test_unreachable_target_gives_nothing(lab):
    lab.raise_on = "sh -s"
    assert complete.complete(["run", "lab", ""], lab) == []
    lab.raise_on = None
    lab.canned["sh -s"] = (255, b"ssh failed")
    assert complete.complete(["run", "lab", ""], lab) == []


def test_main_prints_candidates_and_never_fails(lab, capsys, monkeypatch):
    assert cli.main(["__complete", "ru"]) == 0
    assert capsys.readouterr().out == "run\n"
    monkeypatch.setattr(complete, "complete", lambda w: (_ for _ in ()).throw(OSError("boom")))
    assert cli.main(["__complete", "run", "lab", ""]) == 0
    assert capsys.readouterr().out == ""


def test_default_transport_is_ssh(lab, monkeypatch):
    from conning import transport

    monkeypatch.setattr(transport.SSHTransport, "exec", lambda self, t, c, **kw: (0, b"--conning-live--\nok\n"))
    assert complete.remote("lab", [], "o") == ["ok"]


@pytest.mark.parametrize("shell", sorted(complete.SHELLS))
def test_completion_scripts(shell, capsys):
    assert cli.main(["completion", shell]) == 0
    assert "conn __complete" in capsys.readouterr().out


@pytest.mark.skipif(subprocess.run(["bash", "-c", "true"]).returncode != 0, reason="needs bash")
def test_bash_script_passes_the_words(tmp_path):
    fake = tmp_path / "conn"
    fake.write_text('#!/bin/sh\nprintf "%s|" "$@"\necho\n')
    fake.chmod(0o755)
    script = complete.SHELLS["bash"] + 'COMP_WORDS=(conn run lab ""); COMP_CWORD=3; _conn; echo "${COMPREPLY[@]}"'
    env = {"PATH": f"{tmp_path}:/usr/bin:/bin"}
    out = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env)
    assert out.stdout.strip() == "__complete|run|lab||"


def test_history_flag_in_the_target_file(home):
    from conning import paths
    from conning.targets import TargetFileError, dump_targets, load_targets

    assert "history = false" in dump_targets({"lab": target("lab", history=False)})
    assert "history" not in dump_targets({"lab": target("lab")})
    paths.targets_file().write_text('[lab]\nhost = "h"\nuser = "u"\nhistory = "no"\n')
    with pytest.raises(TargetFileError, match="'history' must be true or false"):
        load_targets(paths.targets_file())
