"""Edge cases of the small pure modules: remote scripts, output capping, policy, paths, the target file."""

import pytest

from conning import paths, remote
from conning.output import render
from conning.policy import split_command, words
from conning.targets import TargetFileError, _toml_value, load_targets


def test_remote_rejects_unsafe_ids_and_signals():
    with pytest.raises(ValueError, match="bad job id"):
        remote.posix_poll("../x", 0, 10)
    with pytest.raises(ValueError, match="delimiter"):
        remote.posix_start("ab12", "echo CONNING_EOF_ab12", cwd=None, timeout=5, env={})
    with pytest.raises(ValueError, match="unsupported signal"):
        remote.posix_signal("ab12", "HUP")
    with pytest.raises(ValueError, match="unexpected poll output"):
        remote.parse_poll(b"garbage\n")


def test_a_windows_poll_reply_survives_clixml_on_stderr():
    # Windows PowerShell may write progress CLIXML to stderr, and ssh merges it into the reply.
    noise = b'#< CLIXML\r\n<Objs Version="1.1.0.1"><Obj S="progress"/></Objs>'
    assert remote.parse_poll(noise + b"\nCONNING-RC 0 5\nhello" + noise) == (0, b"hello")
    assert remote.parse_poll(b"CONNING-RC - 0\n" + noise) == (None, b"")
    assert remote.parse_poll(b"CONNING-RC 3\nposix output") == (3, b"posix output")


def test_pwsh_scripts():
    script = remote.pwsh_script("Get-Item x", cwd="C:\\it's", env={"TOKEN": "a'b"})
    assert "$env:TOKEN = 'a''b'" in script and "Set-Location -LiteralPath 'C:\\it''s'" in script
    assert remote.pwsh_read_file("C:\\log.txt", None) == "Get-Content -LiteralPath 'C:\\log.txt'"
    assert remote.pwsh_read_file("f", "-5").endswith("-Tail 5")
    assert remote.pwsh_read_file("f", "10-12").endswith("Select-Object -Skip 9 -First 3")
    assert remote.pwsh_read_file("f", "10-").endswith("Select-Object -Skip 9")


def test_one_enormous_line_keeps_its_end():
    out = render("exit=0", "x" * 100 + "END", max_bytes=60)
    assert len(out.encode()) <= 60 and out.endswith("END")
    tiny = render("exit=0 " + "h" * 80, "y" * 500, max_bytes=40)
    assert len(tiny.encode()) <= 40


def test_policy_edges():
    assert split_command("echo 'unbalanced") is None
    assert split_command("   ") is None
    assert words([]) == ()


def test_config_dir_defaults(monkeypatch, tmp_path):
    monkeypatch.delenv("CONNING_HOME", raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    if paths.os.name != "nt":
        assert paths.config_dir() == tmp_path / "conning"
    monkeypatch.setattr(paths.os, "name", "nt")

    class FakePath:  # a WindowsPath cannot be built on POSIX; any Path will do for the join logic
        def __new__(cls, *parts):
            return tmp_path.joinpath(*map(str, parts))

        home = staticmethod(lambda: tmp_path)

    monkeypatch.setattr(paths, "Path", FakePath)
    monkeypatch.setenv("APPDATA", str(tmp_path / "AppData"))
    assert paths.config_dir() == tmp_path / "AppData" / "conning"


def test_target_file_edges(tmp_path):
    f = tmp_path / "targets.toml"
    f.write_text('lab = "not a table"\n')
    with pytest.raises(TargetFileError, match="expected a table"):
        load_targets(f)
    f.write_text('[lab]\nhost = "h"\nuser = "u"\ninject = { TOKEN = 3 }\n')
    with pytest.raises(TargetFileError, match="inject"):
        load_targets(f)


def test_toml_values():
    assert _toml_value(True) == "true" and _toml_value(False) == "false"
    assert _toml_value({"A": "env:X"}) == '{ A = "env:X" }'
    with pytest.raises(TypeError):
        _toml_value(1.5)


def test_state_dir_defaults(monkeypatch, tmp_path):
    monkeypatch.setenv("CONNING_STATE", str(tmp_path / "s"))
    assert paths.state_dir() == tmp_path / "s"
    monkeypatch.delenv("CONNING_STATE")
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "xdg"))
    if paths.os.name != "nt":
        assert paths.state_dir() == tmp_path / "xdg" / "conning"
    monkeypatch.setattr(paths.os, "name", "nt")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "Local"))

    class FakePath:
        def __new__(cls, *parts):
            return tmp_path.joinpath(*map(str, parts))

        home = staticmethod(lambda: tmp_path)

    monkeypatch.setattr(paths, "Path", FakePath)
    assert paths.state_dir() == tmp_path / "Local" / "conning" / "state"
