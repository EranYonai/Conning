import asyncio
import json
import re
from pathlib import Path

from conning.cli import help_markdown, main
from conning.server import build_server

README = Path(__file__).resolve().parents[1] / "README.md"


def test_readme_caches_current_cli_help():
    """D10: agents read CLI help from the README. Regenerate with `conn help --markdown`."""
    block = re.search(r"<!-- conn-help:start -->\n(.*?)\n<!-- conn-help:end -->", README.read_text(), re.S)
    assert block, "README.md is missing the conn-help block"
    assert block.group(1) == help_markdown()


def test_targets_command(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("CONNING_HOME", str(tmp_path))
    assert main(["targets"]) == 0
    assert "no targets" in capsys.readouterr().out


def test_server_has_exactly_four_tools_and_a_small_schema():
    tools = asyncio.run(build_server().list_tools())
    assert sorted(t.name for t in tools) == ["read", "run", "targets", "transfer"]
    assert all(t.output_schema is None for t in tools)  # results are text only, never sent twice (D50)
    size = len(json.dumps([t.model_dump(by_alias=True, exclude_none=True) for t in tools]))
    assert size < 2600, f"tool schemas grew to {size} chars; every char costs context on every turn"
