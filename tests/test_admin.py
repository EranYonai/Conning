import pytest
from conftest import target, write_targets

from conning import admin, paths, ssh
from conning.state import Approval
from conning.targets import load_targets

KEYS = [("ssh-ed25519", "SHA256:abc", "QUFB")]


class FakeIO:
    def __init__(self, *answers, tty=True):
        self.tty = tty
        self.answers = list(answers)
        self.said: list[str] = []

    def ask(self, prompt):
        self.said.append(prompt)
        return self.answers.pop(0)

    def secret(self, prompt):
        self.said.append(prompt)
        return self.answers.pop(0)

    def say(self, text):
        self.said.append(text)

    @property
    def text(self):
        return "\n".join(self.said)


@pytest.fixture
def keyscan(monkeypatch):
    state = {"keys": KEYS}
    monkeypatch.setattr(ssh, "scan_host_keys", lambda host, port: state["keys"])
    return state


@pytest.fixture
def keychain(monkeypatch):
    stored = {}

    def store(account, value):
        stored[account] = value
        return f"keychain:conning/{account}"

    monkeypatch.setattr(admin, "store_in_keychain", store)
    return stored


def saved(name="lab"):
    return load_targets(paths.targets_file()).get(name)


# --- add ----------------------------------------------------------------------------------------


def test_agent_add_without_tty_is_pending(core):
    io = FakeIO(tty=False)
    assert admin.add(core, io, "lab", host="192.0.2.10", user="tester", tags=["x"]) == 0
    t = saved()
    assert t.status == "pending" and t.tags == ("x",) and t.auth == "ssh-agent"
    assert "conn approve lab" in io.text


def test_add_validations(core):
    assert admin.add(core, FakeIO(tty=False), "bad name!", host="h", user="u") == 1
    assert admin.add(core, FakeIO(tty=False), "lab", host="h", user="u", mode="yolo") == 1
    io = FakeIO(tty=False)
    assert admin.add(core, io, "lab") == 1 and "--host and --user" in io.text
    io = FakeIO(tty=False)
    assert admin.add(core, io, "lab", host="h", user="u", auth="telnet") == 1 and "auth must be" in io.text
    io = FakeIO(tty=False)
    assert admin.add(core, io, "lab", host="h", user="u", auth="key") == 1 and "needs --key" in io.text
    write_targets(target())
    io = FakeIO(tty=False)
    assert admin.add(core, io, "lab", host="h", user="u") == 1 and "conn approve lab" in io.text


def test_add_reports_a_broken_target_file(core):
    paths.targets_file().write_text("not toml [")
    io = FakeIO(tty=False)
    assert admin.add(core, io, "lab", host="h", user="u") == 1 and io.text.startswith("error:")


def test_interactive_add_with_password_pins_and_probes(core, transport, keyscan, keychain):
    transport.canned["uname -s"] = (0, b"Linux\n")
    io = FakeIO("192.0.2.10", "tester", "password", "pw-typed", "y")
    assert admin.add(core, io, "lab", key=None) == 0
    t = saved()
    assert t.status == "active" and t.os == "linux" and t.shell == "bash" and t.hostkey == "SHA256:abc"
    assert t.secret == "keychain:conning/lab" and keychain == {"lab": "pw-typed"}
    assert "pw-typed" not in io.text
    assert "conning-lab ssh-ed25519 QUFB" in (paths.config_dir() / "known_hosts").read_text()


def test_interactive_add_with_key_prompts_for_the_file(core, transport, keyscan):
    transport.canned["uname -s"] = (0, b"Darwin\n")
    io = FakeIO("key", "~/.ssh/id_lab", "yes")
    assert admin.add(core, io, "lab", host="h", user="u") == 0
    assert saved().key == "~/.ssh/id_lab" and saved().os == "darwin"
    io = FakeIO("key", "")
    assert admin.add(core, io, "lab2", host="h", user="u") == 1 and "needs --key" in io.text


def test_auth_is_inferred_from_secret_or_key(core):
    admin.add(core, FakeIO(tty=False), "a", host="h", user="u", secret="env:X")
    admin.add(core, FakeIO(tty=False), "b", host="h", user="u", key="/k")
    assert saved("a").auth == "password" and saved("b").auth == "key"
    admin.add(core, FakeIO(tty=False), "w", host="h", user="u", os_name="windows")
    assert saved("w").shell == "pwsh"


def test_enroll_declined_or_failing(core, transport, keyscan, monkeypatch):
    io = FakeIO("n")
    assert admin.add(core, io, "lab", host="h", user="u", auth="ssh-agent") == 1
    assert "stays pending" in io.text and saved().status == "pending"

    keyscan["keys"] = []
    monkeypatch.setattr(ssh, "port_open", lambda h, p, timeout=3: True)
    io = FakeIO()
    assert admin.approve_target(core, io, "lab") == 1 and "no host keys" in io.text
    monkeypatch.setattr(ssh, "port_open", lambda h, p, timeout=3: False)
    monkeypatch.setattr(ssh, "no_ssh_hint", lambda t: "windows hint")
    io = FakeIO()
    assert admin.approve_target(core, io, "lab") == 1 and "windows hint" in io.text

    def boom(host, port):
        raise ssh.SSHError("ssh-keyscan not found")

    monkeypatch.setattr(ssh, "scan_host_keys", boom)
    io = FakeIO()
    assert admin.approve_target(core, io, "lab") == 1 and "ssh-keyscan" in io.text


def test_enroll_probe_failure_keeps_pending(core, transport, keyscan):
    transport.canned["uname -s"] = (255, b"Permission denied")
    io = FakeIO("y")
    assert admin.add(core, io, "lab", host="h", user="u", auth="ssh-agent") == 1
    assert "explained rc=255" in io.text and saved().status == "pending"


# --- probe --------------------------------------------------------------------------------------


def test_probe_falls_back_to_powershell(core, transport):
    transport.canned["uname -s"] = (1, b"not recognized")
    transport.canned["pwsh "] = (1, b"")
    transport.canned["powershell "] = (0, b"5\n")
    assert admin.probe(core, target()) == ("windows", "powershell", None)
    transport.canned["powershell "] = (1, b"")
    assert admin.probe(core, target())[2].startswith("could not detect")


def test_probe_ssh_error(core, transport):
    transport.raise_on = "uname"
    assert admin.probe(core, target())[2] == "boom"


# --- approve ------------------------------------------------------------------------------------


def test_approve_needs_a_tty(core):
    io = FakeIO(tty=False)
    assert admin.approve(core, io, "lab") == 1 and "interactive terminal" in io.text
    assert admin.approve_target(core, FakeIO(tty=False), "lab") == 1


def test_approve_target(core, transport, keyscan, keychain):
    write_targets(target(status="pending"))
    transport.canned["uname -s"] = (0, b"Linux\n")
    assert admin.approve(core, FakeIO("y"), "lab") == 0 and saved().status == "active"
    io = FakeIO()
    assert admin.approve(core, io, "ghost") == 1 and "no target ghost" in io.text


def test_approving_a_target_in_auto_says_so(core, transport, keyscan, keychain):
    write_targets(target(status="pending", mode="auto"))  # an agent may propose auto; the human sees it
    transport.canned["uname -s"] = (0, b"Linux\n")
    io = FakeIO("n")
    assert admin.approve(core, io, "lab") == 1 and saved().status == "pending"
    assert "mode=auto" in io.text and "the agent runs anything without asking?" in io.text


def test_agent_cannot_add_a_password_target_without_a_reference(core):
    io = FakeIO(tty=False)
    assert admin.add(core, io, "lab", host="h", user="u", auth="password") == 1
    assert "--secret" in io.text and saved() is None


class StubCore:
    """Stands in for the engine when approving: records what the human's terminal would show."""

    def __init__(self):
        self.reads = []

    def read(self, what, wait=0):
        self.reads.append((what, wait))
        return f"exit=0 for {what}"


STUB = StubCore()


def approval(**kw):
    a = Approval(
        id="ab12", targets=["lab"], command=None, argv=["pytest", "-x", "tests"], cwd="/w", timeout=60, created=0.0
    )
    for k, v in kw.items():
        setattr(a, k, v)
    a.save()
    return a


def test_approve_command_once(home):
    write_targets(target())
    approval()
    io = FakeIO("a")
    assert admin.approve(STUB, io, "a:ab12") == 0
    assert Approval.load("ab12").status == "approved" and saved().allow == ()
    assert "exit=0 for a:ab12" in io.text  # the human sees the result without a second command
    assert "(cwd /w)" in io.text and "always allow 'pytest tests'" in io.text


def test_approve_command_always_remembers_two_words(home):
    write_targets(target())
    approval()
    io = FakeIO()
    assert admin.approve(STUB, io, "a:ab12", always=True) == 0
    assert saved().allow == (("pytest", "tests"),)
    approval(status="pending")
    admin.approve(STUB, FakeIO("e"), "a:ab12")
    assert saved().allow == (("pytest", "tests"),)  # not added twice


def test_deny_and_unknown_and_already_decided(home):
    write_targets(target())
    approval()
    assert admin.approve(STUB, FakeIO("d"), "a:ab12") == 0 and Approval.load("ab12").status == "denied"
    io = FakeIO()
    assert admin.approve(STUB, io, "a:ab12") == 0 and "already denied" in io.text
    io = FakeIO()
    assert admin.approve(STUB, io, "a:ffff") == 1 and "no approval" in io.text


def test_shell_syntax_command_can_only_be_allowed_once(home):
    write_targets(target())
    approval(argv=None, command="make | tee log", cwd=None)
    io = FakeIO("e")
    admin.approve(STUB, io, "a:ab12")
    assert "[a]llow once, [d]eny" in io.text and Approval.load("ab12").status == "denied"


# --- rm, test ----------------------------------------------------------------------------


def test_remove(home):
    write_targets(target())
    ssh.pin_host_keys("lab", KEYS)
    assert admin.remove(FakeIO(), "lab") == 0
    assert saved() is None and "conning-lab" not in (paths.config_dir() / "known_hosts").read_text()
    assert admin.remove(FakeIO(), "lab") == 1


def test_test_command(core, transport):
    write_targets(target(), target("p", status="pending"))
    transport.canned["uname -s"] = (0, b"Linux\n")
    io = FakeIO()
    assert admin.test(core, io, "lab") == 0 and "ok, linux bash" in io.text
    assert admin.test(core, FakeIO(), "p") == 1
    assert admin.test(core, FakeIO(), "ghost") == 1
    transport.canned["uname -s"] = (255, b"x")
    io = FakeIO()
    assert admin.test(core, io, "lab") == 1 and "explained" in io.text


def test_console_io_say(capsys):
    admin.ConsoleIO().say("hi")
    assert capsys.readouterr().out == "hi\n"


# --- import -------------------------------------------------------------------------------------


def test_import_ssh_config(home, tmp_path):
    config = tmp_path / "config"
    config.write_text(
        """
# comment
Host lab-lin1 lab-lin2
  HostName 192.0.2.11
  User tester
  Port 2222
  IdentityFile ~/.ssh/id_lab
  ForwardAgent yes
Host *.example wild*
  User nobody
Match host foo
  User ignored
Host plain
  ProxyCommand none
Host bad!name
"""
    )
    write_targets(target("plain"))
    io = FakeIO()
    assert admin.import_ssh_config(io, "*", config) == 0
    t = saved("lab-lin1")
    assert (t.host, t.user, t.port, t.auth, t.key, t.status) == (
        "192.0.2.11",
        "tester",
        2222,
        "key",
        "~/.ssh/id_lab",
        "pending",
    )
    assert saved("lab-lin2") is not None and "imported 2 target(s)" in io.text
    assert "forwardagent" in io.text and "proxycommand" not in io.text


def test_import_match_and_missing(home, tmp_path):
    config = tmp_path / "config"
    config.write_text("Host one\n  HostName 192.0.2.1\nHost two\n")
    io = FakeIO()
    admin.import_ssh_config(io, "nothing*", config)
    assert "imported 0 target(s) as pending: -" in io.text
    io = FakeIO()
    assert admin.import_ssh_config(io, "*", tmp_path / "nope") == 1 and "not found" in io.text


def test_targets_shows_why_a_target_is_pending(core, transport, keyscan):
    """From Eran's agent: a pending target with a pinned key gave no reason."""
    transport.canned["uname -s"] = (255, b"ssh: connect to host 192.0.2.10 port 22: Connection reset")
    transport.explain = lambda t, rc, out: out.decode()
    admin.add(core, FakeIO("y"), "lab", host="192.0.2.10", user="u", auth="ssh-agent")
    line = core.targets()
    assert "mode=pending (login check failed: ssh: connect to host <host> port 22" in line
    assert line.count("192.0.2.10") == 1  # in host=, not repeated in the reason
    transport.canned["uname -s"] = (0, b"Linux\n")
    assert admin.approve(core, FakeIO("y"), "lab") == 0
    assert core.targets().endswith("mode=ask")


def test_declined_pin_and_missing_keys_are_recorded(core, keyscan, monkeypatch):
    admin.add(core, FakeIO("n"), "lab", host="h", user="u", auth="ssh-agent")
    assert "pending (host key not confirmed)" in core.targets()
    keyscan["keys"] = []
    monkeypatch.setattr(ssh, "port_open", lambda h, p, timeout=3: False)
    monkeypatch.setattr(ssh, "no_ssh_hint", lambda t: "hint")
    admin.approve(core, FakeIO(), "lab")
    assert "pending (no SSH server answered)" in core.targets()


@pytest.mark.skipif(not __import__("shutil").which("sh"), reason="needs a POSIX sh")
def test_approving_shows_the_result_and_the_agent_still_gets_it(core, home):
    """Found replaying the guide: the human's view used to mark the output as read."""
    write_targets(target())
    out = core.run("lab", argv=["echo", "hello-from-lab"])
    approval_id = out.split("id=a:")[1].split()[0]
    io = FakeIO("a")
    assert admin.approve(core, io, f"a:{approval_id}") == 0
    assert "hello-from-lab" in io.text
    assert "hello-from-lab" in core.read(f"a:{approval_id}")


def test_mode_shows_turns_auto_on_with_a_human_and_back_from_anywhere():
    from conning import audit

    write_targets(target(), target("lab2", tags=("x",)))
    io = FakeIO(tty=False)
    assert admin.set_mode(io, "lab", None) == 0 and io.text == "lab: mode=ask"
    assert admin.set_mode(FakeIO(tty=False), "nope", "auto") == 1
    io = FakeIO(tty=False)
    assert admin.set_mode(io, "lab", "auto") == 1 and "needs a human" in io.text
    io = FakeIO("n")
    assert admin.set_mode(io, "lab", "auto") == 1 and "no change" in io.text and saved().mode == "ask"
    io = FakeIO("y")
    assert admin.set_mode(io, "lab,lab2", "auto") == 0 and "run anything on lab, lab2" in io.said[0]
    assert saved().mode == "auto" and saved("lab2").mode == "auto"
    io = FakeIO(tty=False)
    assert admin.set_mode(io, "tag:x", "auto") == 0 and io.text == "already mode=auto"
    io = FakeIO(tty=False)
    assert admin.set_mode(io, "tag:x", "ask") == 0 and io.text == "mode=ask on lab2"
    changes = [(e["target"], e["mode"]) for e in audit.read_from(0)[0] if e.get("change") == "mode"]
    assert changes == [("lab", "auto"), ("lab2", "auto"), ("lab2", "ask")]
