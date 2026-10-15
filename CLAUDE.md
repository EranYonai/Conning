# Working on Conning

Conning is an MCP server and CLI that let a developer's own agent run commands on remote test
machines ("targets") without seeing their secrets. Read [docs/design.md](docs/design.md) before
changing behavior; every decision there has a number (D1...) and a status.

## Principles

- Prompt text is advice; the toolset is a wall. Guardrails live in code, and default to deny.
- Fewer tools beat more tools. The agent gets exactly four: targets, run, read, transfer. Adding a
  tool or growing a docstring costs context on every turn; `tests/test_cli_and_server.py` caps it.
- No tool ever returns a secret, adds a live target or changes policy.
- Lead every result with the fact the agent branches on (exit code or status). Never exceed `max_bytes`.
- The target file is fail-closed: unknown keys and bad values are errors.
- Never put real hostnames, IPs or credentials in code, tests or docs. Placeholders only.

## Commands

```sh
uv sync
uv run pytest --cov=conning   # keep coverage at 95%+; mock SSH with the fake transport in tests/conftest.py
uv run ruff check && uv run ruff format --check
uv run conn help --markdown   # paste into README.md between the conn-help markers after CLI changes
```

## Docs

When a decision changes, update the table in `docs/design.md` (supersede rows rather than deleting
them) and add a dated post to `docs/blog.html`.
