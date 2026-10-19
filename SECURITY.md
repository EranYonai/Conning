# Security

Conning lets an agent run commands on remote test machines ("targets") without seeing their
credentials. The decisions behind this are numbered in [docs/design.md](docs/design.md).

## Reporting a vulnerability

Use GitHub's private vulnerability reporting:
<https://github.com/EranYonai/Conning/security/advisories/new> (the repository's Security tab).
Please don't open a public issue for a vulnerability.

## Credentials

The target file holds references, never secret values:

- `keychain:<service>/<account>`: the OS keychain (macOS Keychain, Windows Credential Manager, Secret
  Service). A password typed into `conn targets add` is stored there. Refused inside a container.
- `op://<vault>/<item>/<field>`: 1Password, read with `op read`.
- `env:<NAME>`: an environment variable of the Conning process.
- ssh-agent, or a key file named by path.

Values are resolved inside Conning when a connection needs them. Passwords reach ssh through an
askpass helper and its environment; injected values reach the target over stdin or a file only the
user can read, deleted as it starts; neither goes on a command line. No tool returns a secret or a
secret reference. Command output, job output and remote files read with `read` are redacted of the
target's resolved secrets (and their base64, URL-encoded and hex forms) before they are saved or
returned. Files copied with `transfer` are copied as they are.

## What only a human can do

The agent gets four tools: `targets`, `run`, `read`, `transfer`. None of them adds a live target,
approves anything or changes policy. These need a human at an interactive terminal:

- `conn approve <target>`: a target the agent (or `conn targets import`) proposed stays pending,
  doing nothing, until a human approves it after seeing its host, host key fingerprint and secret source.
- `conn approve a:<id>`: a command waiting for approval, also answerable in `conn watch` or, when the
  client supports elicitation, in the agent client's own prompt.
- `conn allow`: adding an allow rule. (`conn deny`, which removes one, needs no terminal.)
- `conn targets mode <target> auto`. (Going back to `ask` needs no terminal.)
- `conn targets rename`, `conn ssh` and `conn run -t`.

`conn mcp install` also writes deny rules into the agent client for raw `ssh`, `scp` and `sftp`, these
human-only `conn` commands and reads of Conning's config dir. Those rules match what the agent types,
so they are a guardrail; the four tools are the wall.

## Command policy

Each target has a mode. In `ask` (the default) a command runs without asking only if it is on the
built-in read-only list (`uname`, `df`, `ps`, `systemctl status`..., each with its own argument
check; `safe = false` turns the list off) or matches an allow rule (the first two words, flags
skipped). Anything else returns `status=pending_approval id=a:<id>` and runs only after a human says
once or always. Shell syntax (`;`, `|`, `$(...)`) and wrappers (`sh -c`, `python -c`, `sudo`, `env`...)
always ask. In `auto` anything runs without asking; `conn doctor` warns about every such target.

## SSH

Conning shells out to OpenSSH with a generated config per target and never reads `~/.ssh/config`.
Host keys are pinned in Conning's own known_hosts at approval; a mismatch is a hard failure. Agent and
X11 forwarding, port forwarding and local commands are off on every hop, jump hosts included, and
Conning never connects to an address the agent typed, only to targets. `conn targets import` copies
only the host name, user, port, identity file and a ProxyJump to another target from an ssh config;
it warns about and drops `ForwardAgent`, `ForwardX11`, `LocalForward`, `RemoteForward`,
`DynamicForward` and `ProxyCommand`, and everything else is ignored. Imported targets are pending.

## Prompt injection through remote output

Remote output is data. Results mark it untrusted, the server instructions tell the agent never to
follow instructions in it, and it can't change anything by itself: the agent cannot approve,
add a live target, change a mode or rule, or see a secret, whatever it is told. An injected agent can
still do whatever the tools allow without approval:

- run commands on the read-only list or matching an allow rule, and anything on an `auto` target;
- read any file the target's user can read with `read <target>:<path>` (redacted as above);
- copy files either way with `transfer`, which is not gated by command policy: it can overwrite files
  on a target, and download to any path the user running Conning can write on that machine;
- stop a job Conning started (`read` with `signal`).

Choose what a target's user can reach, and which targets are `auto`, with that in mind. Every command,
decision, approval, file read, transfer and target change is in a hash-chained audit log
(`<state>/audit.jsonl`). It runs as your user, so it is tamper-evident, not tamper-proof.
