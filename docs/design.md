# Conning design

Conning is an MCP server and CLI that run on a developer's own machine. They hold the keys to remote
test machines ("targets") and let the developer's own agent run commands and move files there,
without the agent ever seeing a secret.

The design came out of a structured debate between four sub-agents (product, security, agent
protocol, contrarian), a survey of open-source prior art, and a section-by-section walkthrough with
Eran. The story is in the [development blog](blog.html).

## Shape

```
your agent ──4 MCP tools──▶ conning server ──OpenSSH──▶ targets (Linux, Windows)
   │            (the wall)    │  policy, output spool,
   └── conn CLI (same core) ──┘  jobs, audit log
                               ▲
                     OS keychain / op:// / ssh-agent (resolved at run time)
you: conn targets add · conn approve · conn watch
```

- The agent stays on the laptop. Targets only need inbound SSH; no LLM keys or tunnels on any VM.
- One core, two front ends: the MCP server and the `conn` CLI print identical output.
- Single developer on their own machine; the target file holds no secrets.

## Agent tools

| Tool | Input | Behavior |
|---|---|---|
| `targets` | `filter?, check?` | One line per target: name, OS, shell, host, user, tags, mode. Never a secret. |
| `run` | `target, cmd \| argv, cwd?, wait=30, timeout=3600, max_bytes=8192, grep?` | One target, a list, or `tag:<tag>`. Exit code first. Still running after `wait` seconds: a job id, and the command keeps running (`setsid`), surviving a dropped connection. `wait=0` is async. PowerShell targets get `-EncodedCommand`. |
| `read` | `id, wait?, range?, grep?, signal?, max_bytes?` | Long-polls `j:<job>` for new lines only, slices `o:<output>`, or pages `<target>:<path>`. |
| `transfer` | `source, dest` | `local:` to `<target>:` or back, over the open connection, sha256 checked. |

Results are plain text with a one-line header (`exit=1 dur=4.2s out=o:9f2 (812 lines, 41.0KB; showing
20+60)`); a fast, complete result is just `exit=0` and its output (D50). `--json` is optional. Fan-out groups targets with identical output into one entry. Progress
streams to the human (MCP progress notifications, `conn watch`, a live terminal); the model sees a
call only when it returns, so the agent gets progress by polling `read`.

## Safety

| Mode | Agent can | Default for |
|---|---|---|
| `ask` | allowlisted commands; anything else waits for approval (`status=pending_approval`) | every new target |
| `auto` | anything, without asking, until the human sets `ask` again | never |

- "Always allow" stores the first two words of the command (flags skipped) in the target's allowlist.
- Every target also allows a built-in list of read-only commands (`uname`, `hostname`, `df`, `ps`, `ls`,
  `ip addr`, `systemctl status`, `journalctl`, `Get-Process`...), each with its own argument check so
  `hostname x` or `ip addr add` still ask. The program must be a bare name. File readers (`cat`, `head`,
  `tail`) are not on it. `safe = false` on a target turns the list off.
- Shell wrappers (`sh -c`, `python -c`, `sudo`, `env`...) and shell syntax always ask.
- Agent-added targets are pending until `conn approve`. The human sees host, fingerprint and secret source.
- Secrets: references only (`keychain:`, `op://`, ssh-agent, FIDO). Passwords via an askpass helper.
  Never in argv; output redacted before it is spooled.
- OpenSSH runs with a generated config: pinned host keys (mismatch is a hard fail), all forwarding off.
  Conning never connects to an address the agent typed.
- `conn mcp install` writes agent permission rules denying raw `ssh`/`scp` and reads of Conning's config.
- Audit log (`<state>/audit.jsonl`): one JSON line per command, decision, approval, rule and
  target change, each carrying the sha256 of the line before it. `conn doctor` reports a broken chain.
  Tamper-evident, not tamper-proof: it runs as your user.

## Approvals (M2)

A command that waits for the human can be answered three ways, all through one function so they
remember the same rule and leave the same audit entry:

1. **In the agent client** (on by default; `conn mcp --no-approve-in-client` turns it off). The `run` tool asks through MCP
   elicitation *before* the command is queued: once, always, or deny. On protocol 2026-07-28 the
   question rides an `input_required` result and the client retries the call with the answer; older
   clients get a mid-call `elicitation/create`. The question depends only on the call's arguments, so a
   retry sees the same one. This works with any MCP client that supports elicitation; for clients that
   don't (url-only ones included, D61), the command simply waits for one of the other two. The protocol
   lets a client answer an elicitation by itself, so turn it off for a client that would do that instead
   of asking you, or behind a proxy that might drop the question ([managed.md](managed.md)).
2. **`conn watch`**, a terminal that prints every event as it happens, new job output, and prompts for
   each pending command.
3. **`conn approve a:<id>`**, as in M1. When a human runs `conn run` at a terminal, it asks right
   there instead and prints the result (D40). A desktop notification (macOS, Linux; `CONNING_NOTIFY=0` turns
   it off) says a command is waiting.

`conn allow <target> <words>` adds a rule after asking at a terminal; `conn deny` removes one and needs
no terminal, since taking trust away is always safe. `conn allow <target>` lists the rules.

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
| ~~D8~~ | ~~Modes observe / ask / lease; new lab targets start in `ask`~~ | Superseded by D52 | superseded |
| D9 | The agent proposes targets; pending until the human approves | One keystroke blocks injected hosts | locked |
| D10 | CLI help cached in the README (generated, tested) | Saves a `--help` round trip per session | locked |
| D11 | Project is Conning (CLI `conn`); machines are "targets" | Free on PyPI and npm; agents know "target" | locked |
| D12 | No `{{secret:x}}` placeholders in agent commands in v0.1 | A placeholder in a free command can leak; `inject` env covers it | proposed |
| D13 | Build our own; adopt ideas from prior art, not dependencies | Learn from open source, keep our own server small and readable | locked |
| D14 | `max_bytes=8192` default argument, raisable to a ceiling | Lean by default, more on demand | locked |
| ~~D14~~ | ~~Ceiling of 64 KB~~ | Superseded by D30 | superseded |
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
| ~~D25~~ | ~~Windows targets run synchronously in M1~~ | Superseded by D43 | superseded |
| D26 | Approvals in M1 are answered at a terminal with `conn approve a:<id>`; one approval covers a whole fan-out | Works today without elicitation; M2 adds `conn watch` and prompts | locked |
| D27 | Unit tests run Conning's real remote scripts with the local `sh` behind a fake transport; CI gates coverage at 95% | Tests the job logic itself without a server | locked |
| D28 | Config dir (targets, pinned keys, leases) is only read when commands run; job output, approvals and generated ssh configs live in a state dir (`XDG_STATE_HOME`, `CONNING_STATE`) | Agent sandboxes mount config read-only; only `add`, `approve`, `rm`, `lease` change trust | locked |
| D29 | `conn run <target> <command...>`: conn's options may sit before or right after the target; the first other word starts the remote command, flags included; `--` optional | Agents write `conn run lab uname -a` and hit argparse errors otherwise | locked |
| D30 | The `max_bytes` ceiling is 16 KB | Eran: 8 to 16 KB; one call never floods the context, paging covers the rest | locked |
| ~~D31~~ | ~~No listing in the official MCP Registry yet~~ | Superseded by D51 | superseded |
| D32 | The tool-schema size stays a test cap, not a published token budget | Eran: no need to publish it | locked |
| ~~D33~~ | ~~Approving in the agent client is opt-in~~ | Superseded by D38 | superseded |
| D38 | Approving in the agent client is on by default for every MCP client that supports elicitation (`--no-approve-in-client` turns it off), asked before the command is queued, through the SDK's resolver so both protocol versions work | Eran: a general MCP for all agents, and in-chat approval should be on; clients without elicitation fall back to `conn watch` / `conn approve` | locked |
| D39 | Every target allows a built-in read-only list (system info, processes, disks, network, service status, logs), checked per command so changing forms still ask; bare program names only; no file readers; `safe = false` opts a target out | Eran (#4): new machines shouldn't need an approval for `uname`; `read` already covers files | locked |
| D40 | `conn run` at a terminal asks right there (once, always, deny) and prints the result; without a terminal it returns `a:<id>` as before. A target name where the command starts is an error that suggests `a,b` | Eran, first real run: copying an id into `conn approve` is clumsy, and the CLI's own hint made a second target name look required | locked |
| ~~D41~~ | ~~`targets` shows the user each target logs in as (never the host or a secret); `conn add <name> --like <target> --user <u>` adds the same machine as another user~~ | Superseded by D59 | superseded |
| D42 | POSIX jobs adopt the PATH of a login shell (`bash -l`, else `sh -l`); the profile's other output is dropped | A non-interactive ssh session skips the profile, so tools in `~/.local/bin` or `/opt` were "not found" (exit 127) | locked |
| D43 | Windows jobs run detached like POSIX ones: the job's wrapper is created through WMI (`Win32_Process.Create`) outside the ssh session, merges stdout and stderr into `~/.conning/jobs/<id>.out`, enforces the timeout on the whole process tree, and is polled by byte offset. Scripts reach PowerShell over stdin, so injected secrets never sit on a command line; they pass to the wrapper in a file only the user can read, deleted as it starts. Where WMI is off, the command runs while connected, as in M1 | Windows OpenSSH ends every process a session started when it closes; a test run must survive a dropped link | locked |
| D44 | `conn mcp install claude\|codex\|cursor` adds the server and denies the agent raw `ssh`/`scp`/`sftp`, the human-only `conn approve`/`lease`/`allow` (and `rename`, D47), and reads of Conning's config dir, in each client's own rule format. Files are merged, never replaced, with a backup; a second run changes nothing; `--dry-run` shows the plan | One command to set up any client; the rules are a guardrail (they match what the agent types), the four tools stay the wall | locked |
| D45 | `conn mcp install` also covers opencode (server under `mcp`, deny rules under `permission`, moved after any catch-all because the last match wins) and pi (server in `~/.pi/agent/mcp.json`; pi has no permission rules, so install says so) | Eran asked for both; both read MCP servers from a JSON file, so each is a small planner | locked |
| D46 | The MCP server also ships as a container image (`ghcr.io/eranyonai/conning`, amd64 and arm64, published from the release workflow on tag): `python:3.13-slim` plus the OpenSSH client, running `conn` as the owner of the volume (an entrypoint drops root to that uid, adding a passwd entry ssh needs), so files on the shared folder stay the human's; dependencies come from `uv.lock`; with `CONNING_HOME=/conning` and `CONNING_STATE=/conning/state` on one volume and `conn mcp` as the entrypoint. `keychain:` references are refused inside a container with a message naming `env:`, `op://` and ssh-agent forwarding; the human-only commands stay on the host, sharing the same volume directory; targets on a lab LAN need `--network host` or a route of their own | Eran (#3): Docker is how many MCP clients install a server. A container can reach neither the OS keychain nor a host terminal, so the image carries only the running half and the human keeps approving where the keys are | locked |
| D47 | `conn rename <old> <new>` renames a target and carries along everything kept under its name: its place in the target file and its rules, pinned host keys, the keychain password `conn add` stored (moved to the new name, so a later `conn add <old>` can't overwrite it; a reference the human chose stays as is), a lease, a pending target's problem, commands still waiting for approval and jobs still running. Finished jobs, answered approvals and the audit log keep the old name, plus a `renamed` entry. It needs a terminal, and `conn mcp install` denies it to the agent | Eran, from field use: names chosen on day one stop fitting, and rm plus add would lose pins, rules and the password | locked |
| D48 | End-to-end tests run the real `conn` and the real MCP server (stdio) against a real OpenSSH server: CI's `e2e` job starts a throwaway sshd on 127.0.0.1 (`tests/e2e/start-sshd.sh`, key and password logins for a throwaway user) and runs `pytest -m e2e`, covering every command in `conn help` (a test fails when one has no e2e test), its options, and the MCP server. Human-only commands run in a pseudo-terminal; typed passwords go to a file keychain (`keyrings.alt`, test only). The tests are marked `e2e` and deselected by default, so the mocked unit suite and its 95% coverage gate are unchanged. Their first run found that ssh's connection sharing (`ControlPath %C`, one socket per host, port and user) let a second target for the same login ride the first one's connection, skipping its own key, password and pinned host key; each target now gets its own socket, named by a hash of its generated config | Eran: Conning is cheap to test end to end, because a local sshd is a real target. Mocks can't catch what OpenSSH itself does, as the shared socket showed | locked |
| D49 | A target can name another target as its jump host (`jump = "gw"`, `conn add --jump gw`; chains allowed). The generated config gets one Host block per hop, each pinned to Conning's own known_hosts under its own alias with forwarding off, linked by ProxyJump; ssh runs every hop with that same file, so `~/.ssh/config` is still never read. Each hop logs in with its own auth, and the askpass helper answers each password prompt by the host key alias ssh names in it. Approving a target behind a jump host fetches its key through the pinned hops with ssh itself (accept-new into a scratch file, no credential offered) and shows it for confirmation. Unknown jump names and loops are target-file errors; a pending hop refuses; `conn rm` keeps a hop in use; `conn rename` updates jumps; `conn import` keeps a ProxyJump to another imported host | Eran asked for jump boxes. D7 promised ProxyJump, but the generated config never had it. Making the jump host a target keeps D7's rules (pinned keys, no forwarding, secret references) on every hop instead of trusting a hop from the user's ssh config | locked |
| D50 | Results are text only: the tools declare no output schema, so the MCP SDK no longer sends each result a second time as `structuredContent` and the schemas lose four "returns a string" blocks (3,052 to 2,454 chars; the test cap drops from 6,000 to 2,600). The header leaves out `dur=` under one second and names the `out=o:<id>` handle only when output is hidden (cut, or filtered by `grep`); `echo hello` returns `exit=0\nhello` (12 chars, was 36) | Measured against three SSH MCP servers on the same sshd: Conning's fixed cost was already the smallest (~1k tokens a turn against ~2k to ~12k), but tiny results carried a 30-char header the others don't, and every result went out twice | locked |
| D51 | Conning is listed in the official MCP Registry as `io.github.EranYonai/conning`, from `server.json` at the repo root: the PyPI package (`uvx conning mcp`) and the GHCR image (with `--network host`, the config folder as its volume and the ssh-agent socket). Ownership markers: an `mcp-name` comment in the README (PyPI) and an `io.modelcontextprotocol.server.name` label (image). The release workflow publishes the listing after the package and the image, logging in with the repository's GitHub OIDC token and setting the versions from the tag | Eran: wide use is the next goal, and the registry is where clients and other directories look for servers. Publishing from CI keeps the listing in step with each release, with no stored token | locked |
| D52 | Two modes, `ask` (the default) and `auto` (anything runs without asking). `observe` and `lease` are gone, and with them `conn lease` and the leases file. The target file stays fail-closed: any other mode is an error that prints the `conn add` line recreating that target (observe becomes ask, lease becomes auto). `conn doctor` warns about every target in `auto`. Older rows that mention a lease (D28, D35, D37, D44, D47) no longer carry one | Eran: everyone already knows ask and auto-approve. Ask with the read-only list already covers what observe was for, a lease mode never did anything on its own, and auto drops the timer in exchange for one mode to remember | locked |
| D53 | Tab completion: `conn completion bash\|zsh\|fish` prints a script that calls a hidden `conn __complete` on every Tab. Subcommands and target names come from the local target file. After `conn run <target>`, one ssh call on the target's shared connection (5 s cap) returns the next word of matching commands from Conning's own audit log and the target's `~/.bash_history`/`~/.zsh_history`, then command names on its PATH (first word) or file names. Only live targets that run the read-only list, or are in `auto` mode, are asked, since a listing is what `ls` shows. Completion never creates an approval and writes nothing to the audit log, so Tab can't flood it. History is on by default; lines that look like they carry a secret (`password`, `token`, `Authorization`, `user:pass@`...) are dropped, which is a heuristic, so `history = false` turns it off per target. Windows targets complete from Conning's log only. Any error prints nothing. `conn completion install` adds the line to the rc file of `$SHELL` once, and `conn doctor` tips it when missing | Eran: Tab after `conn run lab rm` should complete from the machine, including what was typed there before. History is on by default at his call, accepting that an agent with a shell can read it through `conn __complete` unlogged | locked |
| D54 | Managing targets lives under `conn targets <verb>`: `add`, `import`, `test`, `mode`, `rename`, `rm`; `conn targets [filter] [--check]` still lists, exactly as the MCP tool. New `conn targets mode <target> [ask\|auto]` (a name, comma list or `tag:`) shows or sets the mode: turning `auto` on needs a human at a terminal and a confirm, like `allow`; going back to `ask` takes trust away, so it works without one, like `deny`; both are audited, and `conn mcp install` denies agents `conn targets rename` and `conn targets mode`. The top-level `add`, `import`, `test`, `rename`, `rm`, the `ls` alias and `add --retry` (the same as `conn approve <target>`) are gone, with no aliases. `conn -h` and the README block list commands in four sections: agent commands, targets, trust, this machine | Eran: switching a target to auto meant hand-editing the target file, and the flat list of 17 commands repeated itself | locked |
| D55 | `conn run -t/--tty` is for a human at a terminal: one Linux or macOS target, run in a remote pty (`ssh -tt`) with this terminal as its stdin, so spinners, progress bars, colours and prompts show live and can be answered. Same policy as `conn run`: a command that would wait for approval is asked about right there first (once, always or deny, audited), and it refuses without a terminal. The output is redacted as it streams, holding back only a tail that could be the start of a secret. Injected env values go to a file under the jobs dir that deletes itself as it starts, never on argv. `--wait`, `--timeout`, `--max-bytes` and `--grep` don't apply; the exit code is the command's. The MCP tools and plain `conn run` are unchanged | Eran: `conn run` showed loading animations and progress bars as a pile of lines at the end, since a job runs detached with no terminal and is polled. An agent needs the capped, polled result; a human watching wants ssh -t | locked |
| D56 | A finished job's files are deleted from the target as soon as its output and exit code are copied home; the local log is the record from then on. Windows jobs start in `$HOME`, as over ssh, not in the jobs folder | Eran saw `~/.conning/jobs` fill with `.out`, `.pid`, `.rc` and script files that nothing ever removed | locked |
| D57 | `conn mcp install` also writes the Conning skill to the client's own skills folder as `conning/SKILL.md`: Claude Code `~/.claude/skills` (`CLAUDE_CONFIG_DIR`), Codex `~/.codex/skills` (`CODEX_HOME`), Cursor `~/.cursor/skills`, opencode `~/.config/opencode/skills` (`XDG_CONFIG_HOME`), pi `~/.pi/agent/skills`. The skill ships inside the package (`src/conning/skill/SKILL.md`), and a run rewrites it whenever the installed version's copy differs, so upgrading and re-running install refreshes it. It teaches the four tools (pick commands for the target's OS, `wait=0` and `read` for long jobs, `grep` over a bigger `max_bytes`, poll `a:<id>` and never route around a denial) and none of the human-only commands | Eran asked for it: the server instructions and tool docstrings sit in context on every turn, so they stay short, and a skill loads only when a task needs a remote machine, so the advice costs no context on other turns. All five clients read Agent Skills folders, so none is skipped | locked |
| D58 | `conn ssh <target>` opens an interactive shell on one live target for a human at a terminal: plain `ssh -t` with the target's generated config, so its user, key or password (askpass), port, pinned host key and jump hosts all apply and nothing comes from `~/.ssh/config`; only `BatchMode` is off, so a key's passphrase can be typed. Ctrl-C goes to ssh. It refuses without a terminal and on a pending target. No policy check and no redaction, since the human is the one typing; injected env values are not set. The audit log records the shell opening and closing with ssh's exit code. It is not an MCP tool, and `conn mcp install` adds it to the agent's deny rules. `conn -h` gains a fifth section, "At a terminal" | Eran: a plain `conn ssh lab` passthrough, given Conning already holds every ssh setting for the target | locked |
| D59 | `targets` (the tool and `conn targets`) shows each target's host, with `:port` when it isn't 22, next to the user it logs in as; never a secret. `conn add <name> --like <target> --user <u>` still adds the same machine as another user (from D41) | Eran: `conn targets` should show the IP. Where and as whom a target logs in are not secrets, and the agent still can't reach a host except through Conning's tools (`conn mcp install` denies raw ssh) | locked |
| D60 | Every tool has a title and explicit annotations, since the spec assumes destructive and open-world when a hint is unset: `targets` "List targets" (read-only, open-world: `check` probes hosts over ssh); `run` "Run a command" (destructive, open-world); `read` "Read a job, output, approval or file" (not read-only, not destructive, not idempotent, open-world); `transfer` "Copy files" (destructive, open-world). Every parameter has a schema description, each tool's description says what it touches (remote hosts over ssh; `transfer` also the local filesystem of the machine running Conning), whether it can return `status=pending_approval` (only `run`; `read a:<id>` reports it; `read <target>:<path>` and `transfer` are not gated by command policy), that remote content is untrusted data and that Conning's secrets are redacted. Pydantic's generated `title` keys and the `null` branch of optional parameters are stripped from the input schemas (2,454 to 3,286 chars; the test cap moves from 2,600 to 3,300). `read` keeps `signal`; "Make read read-only" (a fifth `stop` tool) was considered and rejected | A gateway or managed client approves tools by name after reading these. `read` can't be honestly read-only anyway: reading `a:<id>` starts a command the human approved. `signal` only stops a job Conning itself started, and marking `read` destructive would make confirm-on-destructive clients prompt on every poll. A fifth tool costs context on every turn (D5) | locked |
| D61 | Managed deployments (an operator pins a version, launches `conning mcp serve` over stdio and approves the tools): a client that declares url-only elicitation falls back to `status=pending_approval` like one with none, mirroring the SDK's own rule (form mode, or a bare `elicitation: {}`), instead of failing the call. `--approve-in-client/--no-approve-in-client` may also follow `serve`. `--no-approve-in-client` is recommended behind a proxy, which may not forward elicitation, or may advertise it and drop it, leaving the call waiting; the human answers with `conn watch` or `conn approve` on the machine running the server, with the same `CONNING_HOME`/`CONNING_STATE`. `conn mcp install <client> --skill-only` writes the skill and the deny rules but no server entry, for an operator who owns the client's MCP config. `docs/managed.md` lists the launch line, every flag and every environment variable; `SECURITY.md` states the threat model and how to report a vulnerability | Operators write the launch args after `serve` and own the MCP config; a url-only client used to get an error, and a dropped elicitation would hang the call | locked |
| D34 | One audit log in the state dir, JSON lines, each with the sha256 of the line before; `conn watch` and `conn doctor` read it | One source for the live view and for after-the-fact review; edits show up | locked |
| D35 | `conn allow` needs a terminal and a yes; `conn deny` does not | Granting trust is human-only (like approve and lease); revoking it is always safe | locked |
| D36 | `conn watch` reads only local files (audit log, job logs) and never contacts a target | Runs beside any number of agents without racing their reads | locked |
| D37 | `conn doctor` checks config and state dirs, ssh tools, keychain, secret sources, pinned keys, leases and the audit chain | The first real user lost time to a read-only sandbox and an unreachable keychain | locked |

## Ideas adopted from prior art

1. Access without exposure: inject the credential, never hand it over (1Password, Infisical, Boundary).
2. Default-deny, deny rules first (Teleport).
3. Mode per target crossed with environment tag, not regex blocklists (tufantunc/ssh-mcp).
4. A timeout that hands control back with a handle instead of killing (OpenHands).
5. Job handles with offset and tail reads (Desktop Commander, E2B).
6. One result envelope everywhere (Fabric, Ansible, pypsrp).
7. Measure the tool-schema cost (mcp-ssh-manager: 37 tools, about 43.5k tokens). Ours is capped in
   `tests/test_cli_and_server.py` (D32).
8. Connector abstraction: SSH now, WinRM/PSRP and local later (pyinfra).
9. Import existing inventory from `~/.ssh/config`.
10. Everything expires: remembered approvals (E2B, Teleport). Leases did too until D52.
11. Fail-closed config: unknown keys are errors (tufantunc/ssh-mcp).
12. A declarative per-target "prepare" recipe for deploying tooling to a VM (devcontainer hooks).

## Milestones

- **M0 (done):** package, CLI surface, MCP server with four tools, target file, output cap,
  allowlist rules, CI and release workflow.
- **M1 (done):** OpenSSH connector (generated config, pinning, askpass), `run`/`read`/`transfer`, job
  table, `add`/`approve`/`import`/`test`/`rm`/`lease` (lease removed by D52), keychain, `op://` and `env:` resolution,
  redaction, approvals by `conn approve a:<id>`.
- **M2 (done):** approvals in the agent client (MCP elicitation) and at the terminal,
  `conn watch`, desktop notifications, hash-chained audit log, `allow`/`deny`, `doctor`, the built-in
  read-only list, `mcp install` with permission rules, detached jobs on Windows.
- **M3 (in progress):** the container image on GHCR (D46), `conn rename` (D47), end-to-end tests in CI (D48), jump hosts (D49), Tab completion from the target (D53), the MCP Registry listing (D51), target commands under `conn targets` with `conn targets mode` (D54), live `conn run --tty` for humans (D55), finished jobs cleaned off the target (D56), `conn ssh` (D58).
- **Next:** wide use.

## Open questions

- When does WinRM become a second connector for old Windows images?
