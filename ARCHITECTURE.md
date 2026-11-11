# AgentShield — Architecture

Reference implementation (Python 3, standard library only). The blueprint's
production system is a Rust daemon + TypeScript MCP adapter; this package is
the auditable reference core with the same component boundaries, so the port
is mechanical.

## Component diagram

```text
AI client / Agent
       |
  ToolCall (tool, action, args, actor, env, user, project)
       |
  Gateway.call()
       |  1. BudgetManager.check()      -- call / time / cost ceilings
       |  2. PolicyEngine.evaluate()    -- deny wins, else allow, else default deny
       |  3. ApprovalStore.is_approved  -- sensitive actions, exact-args token
       |  4. SecretBroker.get()         -- scoped credential for this call only
       |  5. FakeTools.dispatch()       -- the tool runs (or an MCP server, later)
       |  audit every outcome (redacted)
       |
  AuditLog (append-only JSONL)
```

## Modules

| Module | Responsibility | State |
|---|---|---|
| `policy.py` | Policy model (`Rule`, `Policy`), JSON loader, YAML-subset loader with strict validation (unknown fields, duplicate ids, bad effects rejected). | none |
| `engine.py` | Stateless evaluation. Deny rules first, then allow, then default deny. `explain()` returns the same decision plus steps. | none |
| `secrets.py` | `SecretBroker`: env-sourced secrets (`AGENTSHIELD_SECRET_<NAME>`), scoped per tool, tracks handed-out values for redaction. | seen secrets |
| `approval.py` | `ApprovalStore`: pending/approved requests; approval token = SHA-256 of canonical (tool, action, args), so changed args produce a different token. Single-use by default. | pending + approved tokens |
| `budget.py` | `BudgetManager`: max calls, max seconds (injectable clock), max cost. Blocks latch once exceeded. Only executed calls are charged. | counters |
| `audit.py` | `AuditLog`: append-only JSONL; redacts known secrets before writing; `verify()` checks every line parses and has required fields. | file handle (append) |
| `gateway.py` | `Gateway`: the check order above; `ToolCall.to_policy_call()` namespaces resources per tool (`workspace/<path>`, `<env>.<table>`, `<env>`). | composed components |
| `tools.py` | `FakeTools`: files (scoped to a base dir, path-escape checked), a two-environment fake DB, deploy. `TOOL_COSTS` prices each action. | workspace dir, fake DB |

## Check order rationale

Budget first (a run that has spent its budget stops immediately, even for
denied calls — no, denied calls are not charged, but the *check* runs first
so a blown budget cannot be bypassed by a cheap call). Policy second:
authorization never depends on the model's wording. Approval third: only
policy-allowed sensitive actions reach a human. Secrets last: a credential
is fetched only for a call that has already passed every other gate.

## Policy evaluation semantics

- A rule matches when **every** specified field glob-matches the call.
  Unspecified fields match anything.
- Any matching `deny` rule denies (first match named in the reason).
- Otherwise any matching `allow` rule allows.
- Otherwise **default deny**, with the reason saying so explicitly.
- `explain()` runs the identical code path as `evaluate()` — the
  explanation cannot drift from the enforcement.

## Resource namespacing

Tool calls carry raw args; the gateway converts them into policy resources:

- `files` → `workspace/<path>` (absolute paths stay absolute and never
  match the workspace glob — they are denied, and the tool itself also
  rejects paths escaping the base directory as defense in depth).
- `db` → `<environment>.<table>` (e.g. `staging.users`).
- `deploy` → `<environment>`.

## Data flow for one call

```
ToolCall -> budget check -> policy decision -> approval check
         -> secret fetch (db only, scoped) -> tool dispatch
         -> budget.record(cost) -> audit.record(redacted)
```

Every exit path — budget block, policy deny, approval refusal, tool error,
success — writes exactly one audit record.

## What is deliberately not built here

- MCP transport (the proxy adapter is milestone M1 in the blueprint).
- Persistence: policy/approvals are in-memory; audit is a local file.
- Multi-user identity (OAuth/OIDC) and a hosted control plane.
- Sandboxing: the gateway is a policy layer, not a sandbox. A local
  process has the user's own permissions (see THREAT_MODEL.md).
