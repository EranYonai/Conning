# Changelog

## 0.6.3 (2026-10-19)

- `conn ssh <target>` opens an interactive shell on a target with its Conning settings: user, key or
  keychain password, port, pinned host key and jump hosts, nothing from `~/.ssh/config`. It is for a
  human at a terminal, is audited when it opens and closes, and `conn mcp install` denies it to the agent.
- `conn mcp install` also installs the Conning skill into the agent client's skills folder, and refreshes
  it after an upgrade.
- Windows: `conn run` no longer hangs at start (the stdin script ends with a marker line instead of EOF),
  progress records no longer leak into job output, and jobs start in the home folder.
- A finished job's files are deleted from the target once its output is copied home.
- Keychain reads time out instead of hanging, and Ctrl-C exits at once without a traceback.

## 0.6.2 (2026-10-17)

- `conn run -t` (`--tty`) runs a command live in a remote terminal, like `ssh -t`: spinners, progress
  bars and colours draw as they happen, and you can answer prompts or press Ctrl-C. It is for a human at
  a terminal (it refuses without one), runs on one Linux or macOS target, follows the same policy as
  `conn run` (asking first when a command needs approval) and still redacts secrets as output streams.
  Plain `conn run` and the MCP tools are unchanged.

## 0.6.1 (2026-10-17)

- Target commands live under `conn targets`: `conn targets add`, `import`, `test`, `rename` and `rm`.
  `conn targets [filter] [--check]` still lists. The old top-level `add`, `import`, `test`, `rename`,
  `rm`, the `ls` alias and `add --retry` are gone; `conn approve <target>` probes a target again.
- `conn targets mode <target> [ask|auto]` shows or sets a target's mode. Turning `auto` on needs you at
  a terminal and a confirm; going back to `ask` works from anywhere. `conn mcp install` denies agents
  `conn targets mode` and `conn targets rename`; run it again to refresh the rules of an earlier install.
- `conn -h` lists the commands in sections: agent commands, targets, trust, this machine.

## 0.6.0 (2026-10-17)

- Two permission modes: `ask` (the default) and `auto`, which runs anything without asking. `observe`,
  `lease` and `conn lease` are gone; a target file that still names them fails to load and prints the
  `conn add` line that recreates the target. `conn doctor` warns about every target in `auto`.
- Leaner results: text only, with no second `structuredContent` copy and smaller tool schemas. The header
  drops `dur=` under a second and names the `out=` handle only when output is hidden.
- Tab completion: `conn completion bash|zsh|fish` (or `conn completion install`) completes subcommands,
  target names and, after `conn run <target>`, commands, history and file names from the target itself.
- Listed in the official MCP Registry as `io.github.EranYonai/conning`: `server.json` describes the PyPI
  package and the GHCR image, and each release now publishes the listing after the package and the image.

## 0.5.0 (2026-10-16)

- Jump hosts: a target can name another target as its jump host (`conn add lab --host 10.0.0.5
  --user tester --jump gw`, or `jump = "gw"` in the target file; chains work). Every hop gets its own
  pinned, forwarding-off block in the generated ssh config, linked by ProxyJump, and logs in with its
  own auth; with passwords on several hops, each hop gets only its own. Approving a target behind a
  jump host fetches its host key through the pinned hops, sending no credential, for you to confirm.
- `conn import` keeps a ProxyJump to another host it imports, and never saves a jump loop.
- `conn rm` won't remove a jump host other targets use; `conn rename` updates the targets that jump through it.
- A bare ssh failure behind a jump host points at `conn test <jump host>`, since ssh hides the hop's own errors.

## 0.4.0 (2026-10-16)

- Each target gets its own shared ssh connection. Before, two targets for the same host, port and user
  shared one, so the second skipped its own key, password and pinned host key for up to ten minutes.
- End-to-end tests: CI starts a real sshd on the runner and drives every command in `conn help`, each
  of its options and the MCP server (tools, approving in the client, `mcp install` for every client)
  against it, as an agent and as a human at a terminal. A test fails when a command has no e2e test.
- `conn rename <old> <new>`: a target's host keys, stored password, rules, lease, pending approvals and
  running jobs follow it to the new name. Human only (needs a terminal); `conn mcp install` denies it to agents.
- The Docker image is built with `uv sync --frozen` from `uv.lock`, like every other install in the repo.
- `docs/field-test.md` and a **Field report** issue form, for real-use testing across clients, install methods and targets.

## 0.3.0 (2026-10-15)

- The MCP server ships as a container image too: `ghcr.io/eranyonai/conning` (amd64 and arm64),
  built from the OpenSSH client plus Conning, running `conn` as the owner of the `/conning` folder, its
  volume for targets, pinned keys and job output. `keychain:` secrets are refused there with a
  message naming `env:`, `op://` and ssh-agent forwarding, and `conn doctor` says what a container
  changes. Approving stays on the host, sharing the same folder.

## 0.2.0 (2026-10-15)

- Approve commands where you are: in the agent client (MCP elicitation, both protocol versions; on by
  default, `conn mcp --no-approve-in-client` turns it off), in `conn watch`, or with `conn approve`. A desktop notification
  says when a command is waiting (`CONNING_NOTIFY=0` turns it off).
- `conn run` at a terminal asks right there when a command needs approval, and prints the result; a
  target name typed where the command starts is caught with a hint to use `a,b`.
- `conn targets` shows the user each target logs in as; `conn add <name> --like <target> --user <u>` adds the
  same machine as another user.
- Jobs on Linux and macOS targets get the PATH of a login shell, so tools in `~/.local/bin` or `/opt` are found.
- Windows jobs run detached (created through WMI, outside the ssh session), so they survive a dropped
  connection and support `read --signal` and timeouts like POSIX jobs. Scripts reach PowerShell over stdin.
- `conn mcp install claude|codex|cursor|opencode|pi` adds the server and denies raw `ssh`/`scp`/`sftp`, the human-only
  `conn` commands and reads of Conning's config dir (pi has no rules, so only the server); merges with
  existing files and keeps a backup.
- `conn watch`: every command, decision and job exit as it happens, new job output, and approval prompts.
- Audit log in the state dir (`audit.jsonl`), hash-chained; `conn doctor` reports edits.
- Built-in read-only list: `uname`, `hostname`, `df`, `ps`, `ls`, `ip addr`, `systemctl status`, `journalctl`,
  `Get-Process` and more run without asking, checked so changing forms still ask (`safe = false` opts out).
- `conn allow <target> [words]` lists or adds allow rules; `conn deny <target> <words>` removes one.
- `conn doctor` checks the config and state dirs, ssh tools, keychain, secret sources, pinned keys and leases.

## 0.1.0 (unreleased)

- M1: commands run over OpenSSH with a generated per-target config (pinned host key, no forwarding,
  connection reuse) and key, ssh-agent or password auth (keychain, `op://` or `env:` references).
- `run` starts detached jobs on POSIX targets; `read j:<id>` streams new lines, long-polls and sends
  signals; `read o:<id>` pages saved output; `read <target>:<path>` reads remote files.
- `transfer` copies files and directories with scp and checks files by sha256.
- Approvals: commands outside the allowlist wait for `conn approve a:<id>`; leases with `conn lease`.
- `conn add`, `approve`, `import`, `test`, `rm` and `lease` work. Agent-added targets stay pending.
- Secrets and their base64, URL and hex forms are redacted from all output.
- Windows targets run synchronously through PowerShell for now.
- Unit tests with a fake transport; CI gates coverage at 95%.
- `conn run <target> uname -a` passes flags through without `--`; `conn approve a:<id>` prints the result.
- The `max_bytes` ceiling is now 16 KB (was 64 KB).
- Running commands never writes the config dir: job output, approvals and generated ssh configs go to a
  state dir (`XDG_STATE_HOME/conning`, or `CONNING_STATE`). Works with a read-only config, as in agent sandboxes.
- `conn targets` says where it looked when there are none, and why a pending target is pending.
- File and secret problems print one `error:` line (CLI and MCP) instead of a traceback.

## 0.0.1 (unreleased)

- Scaffold: `conn` CLI surface, MCP server with the four agent tools (`targets` works; `run`, `read`,
  `transfer` are stubs for M1), fail-closed target file, output cap with handles, two-word allowlist
  rules, CI, and a PyPI release workflow using Trusted Publishing.
