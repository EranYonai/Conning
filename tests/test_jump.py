"""Jump hosts (D49): a target reached through other targets, each hop pinned and locked down."""

import json
import subprocess
from types import SimpleNamespace

import pytest
from conftest import target, write_targets
from test_admin import KEYS, FakeIO, saved

from conning import admin, askpass, cli, paths, ssh, transport
from conning.targets import TargetFileError, jump_chain, load_targets

KEY = "QUFB"


@pytest.fixture
def fake_ssh(monkeypatch, tmp_path):
    monkeypatch.setattr(ssh.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(ssh, "SHORT_TMP", tmp_path / "tmp")
    (tmp_path / "tmp").mkdir()


def gw(**kw):
    return target("gw", host="192.0.2.1", **kw)


# --- the target file ----------------------------------------------------------------------------


def test_jump_is_saved_and_loaded(home):
    write_targets(gw(), target(jump="gw"))
    assert 'jump = "gw"' in paths.targets_file().read_text()
    targets = load_targets(paths.targets_file())
    assert targets["lab"].jump == "gw" and targets["gw"].jump is None


def test_jump_chain_in_dial_order(home):
    outer, inner = target("outer"), target("inner", jump="outer")
    targets = {t.name: t for t in (outer, inner, target(jump="inner"))}
    assert [t.name for t in jump_chain(targets, targets["lab"])] == ["outer", "inner"]
    assert jump_chain(targets, outer) == []


@pytest.mark.parametrize(
    "toml, error",
    [
        ('[lab]\nhost = "h"\nuser = "u"\njump = 3\n', "'jump' must be the name of another target"),
        ('[lab]\nhost = "h"\nuser = "u"\njump = "bad name"\n', "'jump' must be the name"),
        ('[lab]\nhost = "h"\nuser = "u"\njump = "nowhere"\n', "jump host nowhere is not a target"),
        ('[lab]\nhost = "h"\nuser = "u"\njump = "lab"\n', "jump hosts loop back to lab"),
        ('[a]\nhost = "h"\nuser = "u"\njump = "b"\n[b]\nhost = "h"\nuser = "u"\njump = "a"\n', "loop back"),
    ],
)
def test_bad_jumps_are_errors(home, toml, error):
    paths.targets_file().write_text(toml)
    with pytest.raises(TargetFileError, match=error):
        load_targets(paths.targets_file())


# --- the generated ssh config -------------------------------------------------------------------


def test_each_hop_gets_a_pinned_locked_down_block(tmp_path):
    hops = [target("outer", host="192.0.2.1"), target("inner", host="192.0.2.2", auth="key", key="/k")]
    text = ssh.config_text(target(), tmp_path / "kh", tmp_path / "ctl", hops)
    blocks = text.split("Host ")[1:]
    assert [b.splitlines()[0] for b in blocks] == ["conning-hop-outer", "conning-hop-inner", ssh.ALIAS]
    outer, inner, final = blocks
    assert "ProxyJump" not in outer
    assert "ProxyJump conning-hop-outer" in inner and "ProxyJump conning-hop-inner" in final
    for block, name in zip(blocks, ("outer", "inner", "lab"), strict=True):
        assert f"HostKeyAlias conning-{name}" in block and "StrictHostKeyChecking yes" in block
        assert "ForwardAgent no" in block and "ClearAllForwardings yes" in block
    assert "ControlMaster" not in outer + inner and "ControlMaster auto" in final
    assert 'IdentityFile "/k"' in inner


def test_a_route_change_gets_its_own_shared_connection(tmp_path):
    def socket(hops):
        return ssh.config_text(target(), tmp_path / "kh", tmp_path / "ctl", hops).split("ControlPath ")[1]

    assert socket(None) == socket([])
    assert len({socket(None), socket([target("a")]), socket([target("b")])}) == 3


def test_scan_config_records_the_key_and_offers_no_credential(tmp_path):
    text = ssh.scan_config_text(target(auth="password", secret="env:X"), tmp_path / "kh", tmp_path / "s", [gw()])
    final = text.split(f"Host {ssh.ALIAS}")[1]
    assert "StrictHostKeyChecking accept-new" in final and f'UserKnownHostsFile "{tmp_path / "s"}"' in final
    assert "ProxyJump conning-hop-gw" in final and "IdentityFile none" in final and "IdentityAgent none" in final
    assert "password" not in final
    assert "StrictHostKeyChecking yes" in text.split(f"Host {ssh.ALIAS}")[0]  # the hop stays pinned


# --- connecting ---------------------------------------------------------------------------------


def test_connect_through_a_jump_host(home, fake_ssh, monkeypatch):
    monkeypatch.setenv("GW_PW", "gw-secret")
    monkeypatch.setenv("LAB_PW", "lab-secret")
    write_targets(gw(auth="password", secret="env:GW_PW"), target(auth="password", secret="env:LAB_PW", jump="gw"))
    conn = ssh.connect(saved())
    conf = (paths.state_dir() / "ssh" / "lab.conf").read_text()
    assert conf.startswith("Host conning-hop-gw") and "ProxyJump conning-hop-gw" in conf
    assert json.loads(conn.env["CONNING_ASKPASS_VALUES"]) == {"conning-gw": "gw-secret", "conning-lab": "lab-secret"}
    assert sorted(conn.secrets) == ["gw-secret", "lab-secret"]


def test_a_pending_or_missing_jump_host_is_refused(home, fake_ssh):
    write_targets(gw(status="pending"), target(jump="gw"))
    with pytest.raises(ssh.SSHError, match="jump host gw is pending; a human runs: conn approve gw"):
        ssh.connect(saved())
    with pytest.raises(ssh.SSHError, match="jump host nowhere is not a target"):
        ssh.hops(target(jump="nowhere"))
    assert ssh.hops(target()) == []


def test_hop_passwords_are_redacted_for_a_key_target(home, fake_ssh, monkeypatch):
    monkeypatch.setenv("GW_PW", "gw-secret")
    write_targets(gw(auth="password", secret="env:GW_PW"), target(jump="gw"))
    assert transport.SSHTransport().secrets(saved()) == ["gw-secret"]
    assert transport.SSHTransport().secrets(saved("gw")) == ["gw-secret"]


def test_askpass_answers_each_hop_with_its_own_password():
    pws = {"conning-gw": "one", "conning-lab": "two"}
    assert askpass.answer("tester@conning-gw's password: ", pws) == "one"
    assert askpass.answer("(tester@conning-lab) Password: ", pws) == "two"
    assert askpass.answer("tester@conning-other's password: ", pws) is None  # never someone else's
    assert askpass.answer("Password: ", pws) is None  # can't tell which: nothing
    assert askpass.answer("Password: ", {"conning-lab": "two"}) == "two"


def test_askpass_helper_passes_the_prompt_on(fake_ssh, monkeypatch):
    monkeypatch.setattr(ssh, "IS_WINDOWS_HOST", False)
    assert '"$@"' in ssh._askpass_helper().read_text()
    monkeypatch.setattr(ssh, "IS_WINDOWS_HOST", True)
    assert "%*" in ssh._askpass_helper().read_text()


def test_no_ssh_hint_does_not_probe_past_the_jump_host(monkeypatch):
    monkeypatch.setattr(ssh, "port_open", lambda *a, **k: pytest.fail("probed directly"))
    assert "as seen from gw" in ssh.no_ssh_hint(target(jump="gw"))


# --- fetching the host key through the jump host -------------------------------------------------


def fake_scan(monkeypatch, *, write: str | None, output: bytes = b"", timeout: bool = False):
    seen = {}

    def run(argv, **kw):
        conf = argv[argv.index("-F") + 1]
        text = open(conf).read()
        seen.update(argv=argv, conf=text, env=kw["env"])
        if timeout:
            raise subprocess.TimeoutExpired(argv, 60)
        if write is not None:
            scanned = text.split("UserKnownHostsFile ")[-1].splitlines()[0].strip('"')
            with open(scanned, "w") as f:
                f.write(write)
        return SimpleNamespace(returncode=255, stdout=output)

    monkeypatch.setattr(ssh.subprocess, "run", run)
    return seen


def test_scan_through_the_jump_host(home, fake_ssh, monkeypatch):
    monkeypatch.setenv("GW_PW", "gw-secret")
    seen = fake_scan(monkeypatch, write=f"conning-lab ssh-ed25519 {KEY}\nconning-x ssh-rsa BBBB\n# c\n")
    keys = ssh.scan_host_keys_via(target(jump="gw"), [gw(auth="password", secret="env:GW_PW")])
    assert keys == [("ssh-ed25519", ssh.fingerprint(KEY), KEY)]
    assert seen["argv"][-3:] == [ssh.ALIAS, "--", "exit"] and "accept-new" in seen["conf"]
    assert json.loads(seen["env"]["CONNING_ASKPASS_VALUES"]) == {"conning-gw": "gw-secret"}
    assert not list((ssh.runtime_dir()).glob("tmp*"))  # the scan files are gone


def test_scan_through_the_jump_host_failing(home, fake_ssh, monkeypatch):
    fake_scan(monkeypatch, write=None, output=b"channel 0: open failed: connect failed: Connection refused\n")
    with pytest.raises(ssh.SSHError, match="lab: no host key through gw: connection refused"):
        ssh.scan_host_keys_via(target(jump="gw"), [gw()])
    fake_scan(monkeypatch, write=None, timeout=True)
    with pytest.raises(ssh.SSHError, match="no answer through gw"):
        ssh.scan_host_keys_via(target(jump="gw"), [gw()])


# --- conn add / approve / rm / rename / import ---------------------------------------------------


def test_add_with_a_jump_host(core, transport, monkeypatch):
    write_targets(gw())
    io = FakeIO(tty=False)
    assert admin.add(core, io, "lab", host="10.0.0.5", user="u", jump="gw") == 0 and saved().jump == "gw"
    io = FakeIO(tty=False)
    assert admin.add(core, io, "x", host="h", user="u", jump="nowhere") == 1 and "not a target" in io.text
    io = FakeIO(tty=False)
    assert admin.add(core, io, "y", host="h", user="u", jump="y") == 1
    assert admin.add(core, FakeIO(tty=False), "lab2", like="lab", user="other") == 0
    assert saved("lab2").jump == "gw"  # the same machine, reached the same way


def test_approve_pins_the_key_seen_through_the_jump_host(core, transport, monkeypatch):
    write_targets(gw(), target(jump="gw", status="pending"))
    monkeypatch.setattr(ssh, "scan_host_keys", lambda *a: pytest.fail("scanned directly"))
    monkeypatch.setattr(ssh, "scan_host_keys_via", lambda t, chain: [c.name for c in chain] == ["gw"] and KEYS)
    transport.canned["uname -s"] = (0, b"Linux\n")
    io = FakeIO("y")
    assert admin.approve(core, io, "lab") == 0
    assert "tester@192.0.2.10:22  via gw" in io.text and saved().status == "active"
    assert "conning-lab ssh-ed25519 QUFB" in (paths.config_dir() / "known_hosts").read_text()


def test_approve_waits_for_the_jump_host(core, transport):
    write_targets(gw(status="pending"), target(jump="gw", status="pending"))
    io = FakeIO()
    assert admin.approve(core, io, "lab") == 1
    assert "jump host gw is pending" in io.text and saved().status == "pending"


def test_rm_keeps_a_jump_host_in_use(home):
    write_targets(gw(), target(jump="gw"))
    io = FakeIO()
    assert admin.remove(io, "gw") == 1 and "lab jump through gw" in io.text
    assert admin.remove(io, "lab") == 0 and admin.remove(io, "gw") == 0


def test_rename_follows_into_jumps(home):
    write_targets(gw(), target(jump="gw"))
    assert admin.rename(FakeIO(), "gw", "bastion") == 0
    assert saved().jump == "bastion" and saved("bastion").jump is None


def test_import_keeps_proxyjump_to_another_imported_host(home, tmp_path):
    config = tmp_path / "config"
    config.write_text(
        "Host gw\n  HostName 192.0.2.1\n"
        "Host lab\n  HostName 10.0.0.5\n  ProxyJump gw\n"
        "Host far\n  HostName 10.0.0.6\n  ProxyJump me@192.0.2.9:2222\n"
        "Host plain\n  HostName 10.0.0.7\n  ProxyJump none\n"
    )
    io = FakeIO()
    assert admin.import_ssh_config(io, config=config) == 0
    assert saved().jump == "gw" and saved("far").jump is None and saved("plain").jump is None
    assert "far: ProxyJump me@192.0.2.9:2222 is not a target here" in io.text
    assert "plain" not in io.text.split("imported")[0]


def test_import_proxyjump_to_an_existing_target_or_one_left_out(home, tmp_path):
    config = tmp_path / "config"
    config.write_text("Host gw\n  HostName 192.0.2.1\nHost lab\n  HostName 10.0.0.5\n  ProxyJump gw\n")
    io = FakeIO()
    assert admin.import_ssh_config(io, "lab", config=config) == 0
    assert saved().jump is None and "ProxyJump gw is not a target here" in io.text
    write_targets(gw())
    assert admin.import_ssh_config(FakeIO(), "lab", config=config) == 0
    assert saved().jump == "gw"


def test_cli_passes_jump(home, monkeypatch):
    seen = {}
    monkeypatch.setattr(admin, "add", lambda *a, **k: seen.update(k) or 0)
    assert cli.main(["add", "lab", "--host", "h", "--user", "u", "--jump", "gw"]) == 0
    assert seen["jump"] == "gw"
