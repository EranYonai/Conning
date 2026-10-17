"""`conn rename`: a target's new name takes along everything kept under the old one."""

import json

import pytest
from conftest import target, write_targets
from test_admin import KEYS, FakeIO

from conning import admin, audit, paths, secrets, ssh
from conning.state import Approval, Job, problems, set_problem
from conning.targets import load_targets


class Keyring:
    def __init__(self):
        self.items = {}

    def get_password(self, service, account):
        return self.items.get((service, account))

    def set_password(self, service, account, value):
        self.items[(service, account)] = value

    def delete_password(self, service, account):
        del self.items[(service, account)]


@pytest.fixture
def keyring(monkeypatch):
    ring = Keyring()
    monkeypatch.setattr(secrets, "_keyring", lambda: ring)
    return ring


def test_rename_carries_keys_rules_and_pending_work(home):
    write_targets(target("first"), target("lab", allow=(("make",),), tags=("x",)), target("last"))
    ssh.pin_host_keys("lab", KEYS)
    ssh.pin_host_keys("last", KEYS)
    set_problem("lab", "no SSH server answered")
    waiting = Approval(id="a1", targets=["lab", "last"], command=None, argv=["touch", "x"], cwd=None, timeout=60)
    answered = Approval(id="a2", targets=["lab"], command=None, argv=["ls"], cwd=None, timeout=60, status="approved")
    running = Job(id="j1", target="lab", command="sleep 9", started=0)
    finished = Job(id="j2", target="lab", command="true", started=0, rc=0)
    for record in (waiting, answered, running, finished):
        record.save()
    stale = paths.state_dir() / "ssh" / "lab.conf"
    stale.parent.mkdir(parents=True)
    stale.write_text("x")

    io = FakeIO()
    assert admin.rename(io, "lab", "lab-new") == 0 and io.said == ["renamed lab to lab-new"]

    targets = load_targets(paths.targets_file())
    assert list(targets) == ["first", "lab-new", "last"]  # same place in the file
    assert targets["lab-new"].name == "lab-new" and targets["lab-new"].allow == (("make",),)
    known = (paths.config_dir() / "known_hosts").read_text()
    assert "conning-lab-new ssh-ed25519" in known and "conning-lab " not in known and "conning-last " in known
    assert problems() == {"lab-new": "no SSH server answered"}
    assert Approval.load("a1").targets == ["lab-new", "last"] and Approval.load("a2").targets == ["lab"]
    assert Job.load("j1").target == "lab-new" and Job.load("j2").target == "lab"  # history keeps its name
    assert not stale.exists()
    last = json.loads(audit.log_file().read_text().splitlines()[-1])
    assert last["target"] == "lab-new" and last["change"] == "renamed" and last["was"] == "lab"


def test_rename_moves_the_password_conn_add_stored(home, keyring):
    keyring.set_password("conning", "lab", "pw")
    write_targets(target("lab", auth="password", secret="keychain:conning/lab"))
    assert admin.rename(FakeIO(), "lab", "lab2") == 0
    assert load_targets(paths.targets_file())["lab2"].secret == "keychain:conning/lab2"
    assert keyring.items == {("conning", "lab2"): "pw"}  # a later `conn add lab` can't overwrite it


def test_rename_leaves_a_password_reference_the_human_chose(home, keyring):
    keyring.set_password("vault", "shared", "pw")
    write_targets(target("lab", auth="password", secret="keychain:vault/shared"))
    assert admin.rename(FakeIO(), "lab", "lab2") == 0
    assert load_targets(paths.targets_file())["lab2"].secret == "keychain:vault/shared"
    assert keyring.items == {("vault", "shared"): "pw"}


def test_rename_changes_nothing_when_the_keychain_fails(home, keyring):
    write_targets(target("lab", auth="password", secret="keychain:conning/lab"))  # nothing stored
    io = FakeIO()
    assert admin.rename(io, "lab", "lab2") == 1
    assert "can't move lab's password" in io.text and "nothing changed" in io.text
    assert list(load_targets(paths.targets_file())) == ["lab"]


def test_rename_survives_an_old_password_it_cannot_delete(home, keyring, monkeypatch):
    keyring.set_password("conning", "lab", "pw")
    write_targets(target("lab", auth="password", secret="keychain:conning/lab"))
    monkeypatch.setattr(keyring, "delete_password", lambda *a: (_ for _ in ()).throw(RuntimeError("locked")))
    assert admin.rename(FakeIO(), "lab", "lab2") == 0
    assert ("conning", "lab2") in keyring.items


def test_rename_refusals(home):
    write_targets(target("lab"), target("ci"))
    for args, said in [
        (("ghost", "x"), "error: no target ghost"),
        (("lab", "bad name"), "error: target names use"),
        (("lab", "ci"), "error: ci already exists"),
    ]:
        io = FakeIO()
        assert admin.rename(io, *args) == 1 and said in io.text
    io = FakeIO(tty=False)
    assert admin.rename(io, "lab", "lab2") == 1 and "needs a human at an interactive terminal" in io.text
    assert list(load_targets(paths.targets_file())) == ["lab", "ci"]


def test_rename_with_nothing_pinned(home):
    write_targets(target("lab"))
    assert admin.rename(FakeIO(), "lab", "lab2") == 0
    assert not (paths.config_dir() / "known_hosts").exists()
