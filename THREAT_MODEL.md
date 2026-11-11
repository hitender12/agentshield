# AgentShield — Threat Model

This is the honest security statement for the reference implementation.
Read it before trusting this gateway with anything real.

## What AgentShield is for

Stopping an AI agent — acting on its own reasoning, on a prompt injection,
or on a mistaken instruction — from doing things outside an explicit,
human-written policy: reading the wrong directory, querying production,
deleting files, deploying, or spending money without approval.

## Assets and trust boundaries

| Asset | Protected by |
|---|---|
| Production data (prod DB) | Policy deny rules (`deny-db-prod`); secret scoping (DB credential only handed to the `db` tool, only for allowed calls) |
| Files outside the workspace | Policy resource globs + the file tool's own path-escape check (defense in depth) |
| Irreversible actions (delete/deploy/send/buy) | Human approval bound to exact arguments; single-use |
| Runaway cost / tool-call loops | Call, time, and cost budgets (blocks latch) |
| Secrets in logs | Broker redaction before audit writes |
| Accountability | Append-only audit log with actor, decision, resource, outcome |

## Assumptions (the gateway's security depends on these)

1. **The gateway code and policy files are not attacker-controlled.** If an
   attacker can edit the policy, they can allow anything. Protect policy
   files like code: review changes, restrict write access.
2. **The model is untrusted; the policy is trusted.** Authorization comes
   only from policy evaluated by the gateway, never from model output or
   from page/tool content (tool output is treated as untrusted data).
3. **The host operating system and the user account are not fully
   compromised.** See "What this does NOT protect against" below.
4. **Secrets in the environment are already protected** by the OS (file
   permissions, keychain in local mode, Vault/cloud managers in server
   mode). The broker only *scopes* access; it does not create secrecy
   from nothing.
5. **The human approver actually reads the approval.** An approval that is
   rubber-stamped protects nothing. Approvals show the exact action and
   arguments for this reason.

## What this does NOT protect against

- **A fully compromised host or user account.** A local process has the
  user's own permissions. If malware (or the agent's host process) can
  read the environment, edit policy files, or write the audit log, the
  gateway cannot stop it. The gateway is a policy layer, not a sandbox.
- **A compromised or malicious tool/MCP server.** The gateway checks the
  call before dispatch; it cannot verify what the tool does afterwards.
  A malicious server can exfiltrate whatever data a permitted call returns.
- **Prompt injection in tool output that the *human* acts on.** The gateway
  blocks the agent from executing injected instructions, but if a human
  copies an injected instruction into an approval, that is a human error.
- **Side channels and resource exhaustion outside the gateway** (CPU, disk,
  network from the tool itself). Budgets cap gateway-routed calls only.
- **Audit log tampering by a local attacker.** The log is append-only by
  convention in this implementation, not by cryptographic chaining or
  remote storage. A local attacker with write access can edit it. Tamper
  evidence (hash chaining, remote shipping) is a later milestone.
- **Timing and concurrency attacks.** This reference implementation is
  single-process and in-memory; it has no locking, no rate limiting
  beyond budgets, and no protection against concurrent policy reloads.

## Known limitations of this reference implementation

- No real MCP transport; demo tools are local fakes.
- Policy and approvals live in memory; restarting loses pending approvals.
- The YAML reader is a documented subset, not full YAML — malformed input
  outside the subset raises an error rather than being misinterpreted.
- Audit `verify()` checks structure, not authenticity (no signatures).
- Cost accounting uses static per-tool prices, not measured spend.
- No automated tests for adversarial policy files (fuzz tests are a
  milestone, M6 in the blueprint).

## Security status

**NOT production-secure. Not independently reviewed.** Do not deploy this
reference implementation in front of production systems or real secrets
until it has had an independent security review, a penetration-test scope
(M6 in the blueprint), and the sandboxing/persistence work described in
ARCHITECTURE.md. Use it to learn the design, to test policies, and as a
starting point for the reviewed system.

See SECURITY.md for how to report a vulnerability.
