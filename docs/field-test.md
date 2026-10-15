# Field test: real mileage

[manual-test.md](manual-test.md) proves each feature works once, against a throwaway target. This is
the other half: use Conning for your real work on your real lab machines, through each agent client
and each way of installing it, and write down every place it gets in the way. The aim is friction,
not pass or fail. A command that worked but took three tries is a finding.

## Setup, once

```sh
uv tool install conning            # the CLI on your machine; `conn --version` should say 0.3.0 or later
conn add <name> --host <address> --user <user>    # each lab VM; it asks for the rest (--os windows)
conn approve <name>                # pins the host key
conn doctor                        # every line ok, or a warn you understand
```

Keep `conn watch` open in a spare terminal while you work: it shows every command, approval and job
exit as it happens, and it is where most findings start.

## The matrix

Work through each row for a few sessions of real tasks, not a scripted run. A row is done when it
has carried a day of work without a new finding.

| Run the server with | Client | Targets |
|---|---|---|
| `conn mcp install claude` (uv tool) | Claude Code | Linux, Windows |
| `conn mcp install codex` | Codex CLI | Linux, Windows |
| `conn mcp install cursor` | Cursor | Linux |
| `conn mcp install opencode` | opencode | Linux |
| `uvx conning mcp`, added by hand | any one client | Linux |
| Docker image (README, "Run the server in Docker") | any one client | Linux, Windows |

## Tasks worth giving the agent

Give these as you would to a colleague, in your own words, and let the agent find its way:

1. "What's running on <target>, and how full is its disk?" (the read-only list, no approvals)
2. "Run the test suite on <target> and tell me what failed." (a long job: `wait`, `read`, paging)
3. "Find why <service> restarted last night." (logs, `grep`, remote file reads)
4. "Copy this build to <target> and install it." (transfer, approvals, maybe a lease)
5. "Do the same on all the <tag> machines." (fan-out, collapsed results)
6. Something that should be refused: "ssh into <target> directly", or "show me its password".

## What to write down

For each finding, one field report (the **Field report** form under New issue on GitHub). It asks for:

- what you asked the agent, what it did, and what you expected;
- the client, how the server runs, and the target's OS;
- `conn --version` and `conn doctor`;
- the lines from `conn watch` or `$CONNING_STATE/audit.jsonl` around the moment it went wrong.

**Before you paste, replace hostnames, IP addresses, usernames and anything secret with
placeholders.** The repository is public.

Good findings are specific: "the agent ran `conn run lab lab whoami` twice before it read the
error", "approving in Cursor showed no prompt", "a 40-minute test run came back with exit=124
because the default timeout is an hour but the agent passed 600". Small annoyances count too: they
are what decides whether people keep using it.
