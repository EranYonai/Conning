"""D44: `conn mcp install` adds the server and the deny rules, merges with what is there, and is idempotent."""

import json
import subprocess
from pathlib import Path

import pytest
from test_admin import FakeIO

from conning import cli, install


@pytest.fixture
def fake_home(tmp_path, monkeypatch, home):
    h = tmp_path / "user"
    h.mkdir()
    for var in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(var, str(h))
    for var in ("CLAUDE_CONFIG_DIR", "CODEX_HOME"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(install, "server_command", lambda: ["/opt/bin/conn", "mcp"])
    return h


@pytest.fixture
def no_claude(monkeypatch):
    real = install.shutil.which
    monkeypatch.setattr(install.shutil, "which", lambda name: None if name == "claude" else real(name))


def test_server_command_prefers_the_installed_conn(monkeypatch):
    monkeypatch.setattr(install.shutil, "which", lambda name: "/usr/local/bin/conn")
    assert install.server_command() == ["/usr/local/bin/conn", "mcp"]
    monkeypatch.setattr(install.shutil, "which", lambda name: None)
    assert install.server_command() == ["uvx", "conning", "mcp"]


def test_claude_merges_deny_rules_and_keeps_a_backup(fake_home, home, no_claude):
    settings = fake_home / ".claude" / "settings.json"
    settings.parent.mkdir()
    settings.write_text(json.dumps({"model": "x", "permissions": {"deny": ["Bash(rm *)"], "allow": ["Bash(ls)"]}}))
    io = FakeIO(tty=False)
    assert install.install(io, "claude") == 0
    data = json.loads(settings.read_text())
    deny = data["permissions"]["deny"]
    assert data["model"] == "x" and data["permissions"]["allow"] == ["Bash(ls)"]
    assert (
        deny[0] == "Bash(rm *)" and "Bash(ssh *)" in deny and "Bash(scp *)" in deny and "Bash(conn approve *)" in deny
    )
    assert f"Read(//{home.resolve().as_posix().lstrip('/')}/**)" in deny  # CONNING_HOME is outside this home
    assert (settings.parent / "settings.json.conning.bak").exists()
    assert io.said[0] == f"wrote {settings}"
    assert io.said[-1].startswith("note: claude is not on PATH; add the server with: claude mcp add --scope user")
    io = FakeIO(tty=False)
    assert install.install(io, "claude") == 0
    assert io.said[0] == "claude: already installed, nothing to change"


def test_claude_uses_the_cli_to_add_the_server(fake_home, monkeypatch):
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(fake_home / "cc"))
    monkeypatch.setattr(install.shutil, "which", lambda name: "/bin/claude")
    runs = []

    def run(argv, **kw):
        runs.append(argv)
        return subprocess.CompletedProcess(argv, 1 if argv[2] == "get" else 0, "", "")

    monkeypatch.setattr(install.subprocess, "run", run)
    io = FakeIO(tty=False)
    assert install.install(io, "claude", dry_run=True) == 0
    assert io.said[-1] == "would run /bin/claude mcp add --scope user conning -- /opt/bin/conn mcp"
    assert not (fake_home / "cc").exists()
    assert install.install(FakeIO(tty=False), "claude") == 0
    assert runs[-1] == ["/bin/claude", "mcp", "add", "--scope", "user", "conning", "--", "/opt/bin/conn", "mcp"]
    assert (fake_home / "cc" / "settings.json").exists()

    def fail(argv, **kw):
        return subprocess.CompletedProcess(argv, 1, "", "boom")

    monkeypatch.setattr(install.subprocess, "run", fail)
    io = FakeIO(tty=False)
    assert install.install(io, "claude") == 1
    assert io.said[-1].endswith("failed: boom")


def test_config_dir_under_home_is_written_with_tilde(fake_home, monkeypatch, no_claude):
    monkeypatch.setenv("CONNING_HOME", str(fake_home / ".config" / "conning"))
    install.install(FakeIO(tty=False), "claude")
    deny = json.loads((fake_home / ".claude" / "settings.json").read_text())["permissions"]["deny"]
    assert "Read(~/.config/conning/**)" in deny and "Edit(~/.config/conning/**)" in deny


def test_codex_appends_the_server_and_writes_rules(fake_home):
    config = fake_home / ".codex" / "config.toml"
    config.parent.mkdir()
    config.write_text('model = "o4"\n')
    io = FakeIO(tty=False)
    assert install.install(io, "codex") == 0
    text = config.read_text()
    assert (
        text.startswith('model = "o4"\n')
        and '[mcp_servers.conning]\ncommand = "/opt/bin/conn"\nargs = ["mcp"]\n' in text
    )
    import tomllib

    assert tomllib.loads(text)["mcp_servers"]["conning"] == {"command": "/opt/bin/conn", "args": ["mcp"]}
    rules = (fake_home / ".codex" / "rules" / "conning.rules").read_text()
    assert 'prefix_rule(pattern = ["ssh"], decision = "forbidden"' in rules
    assert 'pattern = ["conn", "lease"]' in rules
    assert io.said[-1].startswith("note: codex rules cover commands only")
    io = FakeIO(tty=False)
    install.install(io, "codex")
    assert io.said[0] == "codex: already installed, nothing to change"


def test_codex_home_and_a_fresh_config(fake_home, monkeypatch):
    monkeypatch.setenv("CODEX_HOME", str(fake_home / "cx"))
    install.install(FakeIO(tty=False), "codex")
    assert (fake_home / "cx" / "config.toml").read_text().startswith("\n[mcp_servers.conning]")


def test_cursor_adds_server_and_cli_permissions(fake_home, home):
    mcp = fake_home / ".cursor" / "mcp.json"
    mcp.parent.mkdir()
    mcp.write_text(json.dumps({"mcpServers": {"other": {"command": "x"}}}))
    io = FakeIO(tty=False)
    assert install.install(io, "cursor") == 0
    servers = json.loads(mcp.read_text())["mcpServers"]
    assert servers["other"] == {"command": "x"}
    assert servers["conning"] == {"type": "stdio", "command": "/opt/bin/conn", "args": ["mcp"]}
    cli_config = json.loads((fake_home / ".cursor" / "cli-config.json").read_text())
    assert cli_config["version"] == 1 and cli_config["permissions"]["allow"] == []
    assert cli_config["permissions"]["deny"][:3] == ["Shell(ssh)", "Shell(scp)", "Shell(sftp)"]
    assert f"Read({home.resolve().as_posix()}/**)" in cli_config["permissions"]["deny"]
    io = FakeIO(tty=False)
    install.install(io, "cursor")
    assert io.said[0] == "cursor: already installed, nothing to change"


def test_unreadable_config_changes_nothing(fake_home):
    bad = fake_home / ".cursor" / "mcp.json"
    bad.parent.mkdir()
    bad.write_text("[1, 2]")
    io = FakeIO(tty=False)
    assert install.install(io, "cursor") == 1
    assert io.said == ["error: can't read the cursor config: expected a JSON object; nothing changed"]
    bad.write_text("{nope")
    assert install.install(FakeIO(tty=False), "cursor") == 1
    assert bad.read_text() == "{nope" and not (fake_home / ".cursor" / "cli-config.json").exists()


def test_cli_wiring(fake_home, monkeypatch):
    seen = []
    monkeypatch.setattr(install, "install", lambda io, client, dry_run: seen.append((client, dry_run)) or 0)
    assert cli.main(["mcp", "install", "codex", "--dry-run"]) == 0
    assert cli.main(["mcp", "install", "cursor"]) == 0
    assert seen == [("codex", True), ("cursor", False)]
    assert Path(fake_home).exists()


def test_opencode_adds_server_and_last_match_deny_rules(fake_home, home, monkeypatch):
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    path = fake_home / ".config" / "opencode" / "opencode.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({"model": "x", "permission": {"bash": {"ssh *": "ask", "*": "allow"}, "edit": "ask"}}))
    io = FakeIO(tty=False)
    assert install.install(io, "opencode") == 0
    data = json.loads(path.read_text())
    assert data["model"] == "x"
    assert data["mcp"]["conning"] == {"type": "local", "command": ["/opt/bin/conn", "mcp"], "enabled": True}
    bash = data["permission"]["bash"]
    assert list(bash)[:3] == ["*", "ssh *", "scp *"]  # moved after the catch-all: the last match wins
    assert bash["ssh *"] == "deny" and bash["conn approve *"] == "deny"
    assert data["permission"]["edit"]["*"] == "ask"
    config = install._home_relative(home, "/")
    assert data["permission"]["read"] == {f"{config}/**": "deny"}
    io = FakeIO(tty=False)
    install.install(io, "opencode")
    assert io.said == ["opencode: already installed, nothing to change"]


def test_opencode_spreads_a_one_word_permission(fake_home, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(fake_home / "xdg"))
    path = fake_home / "xdg" / "opencode" / "opencode.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({"permission": "allow"}))
    install.install(FakeIO(tty=False), "opencode")
    permission = json.loads(path.read_text())["permission"]
    assert permission["*"] == "allow" and permission["bash"]["sftp *"] == "deny"


def test_pi_adds_the_server_and_says_it_has_no_rules(fake_home):
    io = FakeIO(tty=False)
    assert install.install(io, "pi") == 0
    data = json.loads((fake_home / ".pi" / "agent" / "mcp.json").read_text())
    assert data["mcpServers"]["conning"] == {"command": "/opt/bin/conn", "args": ["mcp"]}
    assert io.said[-1].startswith("note: pi has no permission rules")
