"""D41: targets show the login they use, and `conn add --like` adds the same machine as another user.
D42: jobs get the PATH of a login shell, so tools installed under ~/.local/bin are found."""

import test_admin
from conftest import needs_sh, target, write_targets
from test_admin import FakeIO, saved

from conning import admin, cli

keyscan = test_admin.keyscan
keychain = test_admin.keychain


def test_targets_show_the_user(core):
    write_targets(target("lab", user="root"))
    assert core.targets().split() == ["lab", "linux", "bash", "user=root", "tags=-", "mode=ask"]


def test_like_copies_the_machine_and_asks_for_the_new_users_password(core, transport, keyscan, keychain):
    write_targets(target("lab", user="root", port=2222, auth="password", secret="keychain:conning/lab", tags=("db",)))
    transport.canned["uname -s"] = (0, b"Linux\n")
    io = FakeIO("pw-tester", "y")
    assert admin.add(core, io, "lab-tester", user="tester", like="lab") == 0
    t = saved("lab-tester")
    assert (t.host, t.port, t.user, t.tags, t.auth) == ("192.0.2.10", 2222, "tester", ("db",), "password")
    assert t.secret == "keychain:conning/lab-tester" and keychain["lab-tester"] == "pw-tester"
    assert io.said[0] == "password for tester@192.0.2.10: "


def test_like_with_the_same_user_reuses_its_credentials(core, transport, keyscan):
    write_targets(target("lab", user="root", auth="key", key="~/.ssh/id_lab"))
    transport.canned["uname -s"] = (0, b"Linux\n")
    assert admin.add(core, FakeIO("y"), "lab2", like="lab") == 0
    t = saved("lab2")
    assert (t.user, t.auth, t.key) == ("root", "key", "~/.ssh/id_lab")


def test_like_needs_an_existing_target_and_stays_pending_for_agents(core):
    io = FakeIO(tty=False)
    assert admin.add(core, io, "x", user="u", like="nope") == 1 and io.said == ["error: no target nope to copy"]
    write_targets(target("lab", user="root"))
    io = FakeIO(tty=False)
    assert admin.add(core, io, "lab-u", user="u", like="lab") == 0
    assert saved("lab-u").status == "pending" and saved("lab-u").host == "192.0.2.10"


def test_cli_passes_like(monkeypatch):
    seen = []
    monkeypatch.setattr(cli, "_core", lambda: None)
    monkeypatch.setattr(cli, "_io", lambda: None)
    monkeypatch.setattr(admin, "add", lambda *a, **k: seen.append(k) or 0)
    assert cli.main(["add", "lab-u", "--like", "lab", "--user", "u"]) == 0
    assert seen[0]["like"] == "lab" and seen[0]["user"] == "u"


@needs_sh
def test_jobs_find_tools_on_the_login_path(core, transport):
    bin_dir = transport.remote_home / ".local" / "bin"
    bin_dir.mkdir(parents=True)
    tool = bin_dir / "labtool"
    tool.write_text("#!/bin/sh\necho labtool ran\n")
    tool.chmod(0o755)
    (transport.remote_home / ".profile").write_text('echo profile noise\nPATH="$HOME/.local/bin:$PATH"\n')
    write_targets(target("lab", mode="auto"))
    out = core.run("lab", argv=["labtool"], wait=30)
    assert out.startswith("exit=0") and "labtool ran" in out and "noise" not in out


def test_like_keeps_an_explicit_port(core):
    write_targets(target("lab", user="root", port=2222))
    assert admin.add(core, FakeIO(tty=False), "lab22", user="u", port=22, like="lab") == 0
    assert saved("lab22").port == 22
    assert admin.add(core, FakeIO(tty=False), "plain", host="h", user="u") == 0
    assert saved("plain").port == 22
