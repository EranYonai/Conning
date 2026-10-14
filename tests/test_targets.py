import pytest

from conning.targets import TargetFileError, listing, load_targets, select

GOOD = """
[lab-lin1]
host = "10.0.0.5"
user = "root"
auth = "password"
secret = "keychain:lab/lin1"
tags = ["smoke"]
allow = [["pytest"], ["systemctl", "status"]]

[lab-win1]
host = "lab-win1.lab"
user = "tester"
os = "windows"
tags = ["smoke", "win"]
status = "pending"
"""


def write(tmp_path, text):
    p = tmp_path / "targets.toml"
    p.write_text(text)
    return p


def test_loads_and_lists_without_secrets(tmp_path):
    targets = load_targets(write(tmp_path, GOOD))
    assert targets["lab-win1"].shell == "pwsh"
    assert targets["lab-lin1"].mode == "ask"  # D8: new lab targets start in ask
    out = listing(list(targets.values()))
    assert "10.0.0.5" not in out and "root" not in out and "keychain" not in out
    assert "mode=pending" in out


def test_select_by_tag(tmp_path):
    targets = load_targets(write(tmp_path, GOOD))
    assert [t.name for t in select(targets, "tag:win")] == ["lab-win1"]
    assert [t.name for t in select(targets, "lab-lin1,nope")] == ["lab-lin1"]


@pytest.mark.parametrize(
    "bad, message",
    [
        ('[x]\nhost="h"\nuser="u"\nmodee="ask"', "unknown key"),
        ('[x]\nhost="h"\nuser="u"\nmode="yolo"', "mode must be"),
        ('[x]\nhost="h"', "'user' is required"),
        ('[x]\nhost="h"\nuser="u"\nauth="password"', "needs a secret reference"),
        ('[x]\nhost="h"\nuser="u"\nallow=["pytest"]', "'allow' must be"),
        ('["bad name"]\nhost="h"\nuser="u"', "bad target name"),
    ],
)
def test_fails_closed(tmp_path, bad, message):
    with pytest.raises(TargetFileError, match=message):
        load_targets(write(tmp_path, bad))


def test_missing_file_means_no_targets(tmp_path):
    assert load_targets(tmp_path / "nope.toml") == {}
