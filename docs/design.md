# Conning design

Conning is an MCP server and CLI that run on a developer's own machine. They hold the keys to remote
test machines ("targets") and let the developer's own agent run commands and move files there,
without the agent ever seeing a secret.

The design came out of a structured debate between four sub-agents (product, security, agent
protocol, contrarian), a survey of open-source prior art, and a section-by-section walkthrough with
Eran. The story is in [build-log.html](build-log.html).

## Shape

```
your agent ──4 MCP tools──▶ conning server ──OpenSSH──▶ targets (Linux, Windows)
   │            (the wall)    │  policy, output spool,
   └── conn CLI (same core) ──┘  jobs, audit log
                               ▲
                     OS keychain / op:// / ssh-agent (resolved at run time)
you: conn add · conn approve · conn watch
```

- The agent stays on the laptop. Targets only need inbound SSH; no LLM keys or tunnels on any VM.
- One core, two front ends: the MCP server and the `conn` CLI print identical output.
- Single developer on their own machine; the target file holds no secrets.

## Agent tools

| Tool | Input | Behavior |
|---|---|---|
| `targets` | `filter?, check?` | One line per target: name, OS, shell, tags, mode. Never a host, user or secret. |
| `run` | `target, cmd \| argv, cwd?, wait=30, timeout=3600, max_bytes=8192, grep?` | One target, a list, or `tag:<tag>`. Exit code first. Still running after `wait` seconds: a job id, and the command keeps running (`setsid`), surviving a dropped connection. `wait=0` is async. PowerShell targets get `-EncodedCommand`. |
| `read` | `id, wait?, range?, grep?, signal?, max_bytes?` | Long-polls `j:<job>` for new lines only, slices `o:<output>`, or pages `<target>:<path>`. |
| `transfer` | `source, dest` | `local:` to `<target>:` or back, over the open connection, sha256 checked. |

Results are plain text with a one-line header (`exit=1 dur=4.2s out=o:9f2 (812 lines, 41.0KB; showing
20+60)`); `--json` is optional. Fan-out groups targets with identical output into one entry. Progress
streams to the human (MCP progress notifications, `conn watch`, a live terminal); the model sees a
call only when it returns, so the agent gets progress by polling `read`.

## Safety

| Mode | Agent can | Default for |
|---|---|---|
| `observe` | allowlisted read commands only | `shared`, `prod` |
| `ask` | allowlisted commands; anything else waits for approval (`status=pending_approval`) | new lab targets |
| `lease` | anything, for a time box (15 min default, 60 max) | never |

- "Always allow" stores the first two words of the command (flags skipped) in the target's allowlist.
- Shell wrappers (`sh -c`, `python -c`, `sudo`, `env`...) and shell syntax always ask.
- Agent-added targets are pending until `conn approve`. The human sees host, fingerprint and secret source.
- Secrets: references only (`keychain:`, `op://`, ssh-agent, FIDO). Passwords via an askpass helper.
  Never in argv; output redacted before it is spooled.
- OpenSSH runs with a generated config: pinned host keys (mismatch is a hard fail), all forwarding off.
  Conning never connects to an address the agent typed.
- `conn mcp install` writes agent permission rules denying raw `ssh`/`scp` and reads of Conning's config.
- Audit log: append-only, hash-chained, tamper-evident (not tamper-proof: it runs as your user).

## Decisions

| # | Decision | Why | Status |
|---|---|---|---|
| D1 | The agent stays on the dev machine; Conning dials out to targets | No LLM tunnel, handoff zip or LLM keys on VMs | locked |
| D2 | One core, two front ends: MCP server and `conn` CLI, identical output | Approvals and jobs need a long-lived process | locked |
| D3 | Agents with only bash may use the CLI | Works for any harness | locked |
| D4 | Single developer on their own machine | Keep v0.1 small | locked |
| D5 | Four agent tools: targets, run, read, transfer | Schemas cost tokens every turn | locked |
| D6 | No homemade vault; secret references only | Less of our own crypto | locked |
| D7 | Shell out to OpenSSH with generated config, pinned keys, no forwarding | Keep ProxyJump and agents, drop unsafe options | locked |
| D8 | Modes observe / ask / lease; new lab targets start in `ask` | Guardrails in code; works immediately | locked |
| D9 | The agent proposes targets; pending until the human approves | One keystroke blocks injected hosts | locked |
| D10 | CLI help cached in the README (generated, tested) | Saves a `--help` round trip per session | locked |
| D11 | Project is Conning (CLI `conn`); machines are "targets" | Free on PyPI and npm; agents know "target" | locked |
| D12 | No `{{secret:x}}` placeholders in agent commands in v0.1 | A placeholder in a free command can leak; `inject` env covers it | proposed |
| D13 | Build our own; adopt ideas from prior art, not dependencies | Trust ourselves, adopt good ideas | locked |
| D14 | `max_bytes=8192` default argument, raisable to a 64 KB ceiling | Lean by default, more on demand | locked |
| D15 | Progress streams to the human; the agent polls `read` for new lines | Models see a call only when it returns | locked |
| D16 | Async through `wait` (`0` returns a job id at once) | No extra tool | locked |
| D17 | Plain text by default, `--json` on request | About 40% fewer tokens | locked |
| D18 | "Always allow" remembers two words; wrappers always ask | The danger lives in the verb | locked |
| D19 | v0.1 is SSH-only; Windows without OpenSSH gets a fix the agent relays | Some old images lack OpenSSH | locked |
| D20 | Password auth is first-class (keychain + askpass) | Lab VMs are usually root + password | locked |
| D21 | Python, installed with `uv tool install conning` | Same stack as before; official MCP SDK | locked |
| D22 | Public repo, github.com/EranYonai/Conning, Apache-2.0 | Patent grant suits security tooling | locked |
| D23 | PyPI package `conning`, released from CI via Trusted Publishing on tag; `uvx conning mcp` | No stored tokens; one-line MCP setup | locked |
| D24 | POSIX jobs run detached on the target (`$HOME/.conning/jobs`), in their own process group, polled by byte offset | A dropped SSH link never kills a test run; signals reach the whole tree | locked |
| D25 | Windows targets run synchronously in M1 (PowerShell `-EncodedCommand`) | Ship Linux jobs first; detached Windows jobs later | proposed |
| D26 | Approvals in M1 are answered at a terminal with `conn approve a:<id>`; one approval covers a whole fan-out | Works today without elicitation; M2 adds `conn watch` and prompts | locked |
| D27 | Unit tests run Conning's real remote scripts with the local `sh` behind a fake transport; CI gates coverage at 95% | Tests the job logic itself without a server | locked |
| D28 | Config dir (targets, pinned keys, leases) is only read when commands run; job output, approvals and generated ssh configs live in a state dir (`XDG_STATE_HOME`, `CONNING_STATE`) | Agent sandboxes mount config read-only; only `add`, `approve`, `rm`, `lease` change trust | locked |
| D29 | `conn run <target> <command...>`: conn's options may sit before or right after the target; the first other word starts the remote command, flags included; `--` optional | Agents write `conn run lab uname -a` and hit argparse errors otherwise | locked |

## Ideas adopted from prior art

1. Access without exposure: inject the credential, never hand it over (1Password, Infisical, Boundary).
2. Default-deny, deny rules first (Teleport).
3. Mode per target crossed with environment tag, not regex blocklists (tufantunc/ssh-mcp).
4. A timeout that hands control back with a handle instead of killing (OpenHands).
5. Job handles with offset and tail reads (Desktop Commander, E2B).
6. One result envelope everywhere (Fabric, Ansible, pypsrp).
7. Measure and publish the tool-schema cost (mcp-ssh-manager: 37 tools, about 43.5k tokens). Ours is
   checked in `tests/test_cli_and_server.py`.
8. Connector abstraction: SSH now, WinRM/PSRP and local later (pyinfra).
9. Import existing inventory from `~/.ssh/config`.
10. Everything expires: leases and remembered approvals (E2B, Teleport).
11. Fail-closed config: unknown keys are errors (tufantunc/ssh-mcp).
12. A declarative per-target "prepare" recipe for deploying tooling to a VM (devcontainer hooks).

## Milestones

- **M0 (done):** package, CLI surface, MCP server with four tools, target file, output cap,
  allowlist rules, CI and release workflow.
- **M1 (done):** OpenSSH connector (generated config, pinning, askpass), `run`/`read`/`transfer`, job
  table, `add`/`approve`/`import`/`test`/`rm`/`lease`, keychain, `op://` and `env:` resolution,
  redaction, approvals by `conn approve a:<id>`.
- **M2:** approvals in the agent client (MCP elicitation, `conn watch`, OS notification), audit log,
  `doctor`, `mcp install` with permission rules, detached jobs on Windows.
- **Later:** WinRM connector, short-lived SSH certificates, per-target prepare recipes, MCP Registry listing.

## Open questions

- Which ceiling should `max_bytes` have by default (64 KB today)?
- When does WinRM become a second connector for old Windows images?
- Should Conning be listed in the official MCP Registry?
