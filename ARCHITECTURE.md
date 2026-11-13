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
       |  0. BudgetManager.check()      -- call / time / cost ceilings
       |     BudgetManager.record()     -- every attempt is charged here,
       |                                  including env-mismatched and
       |                                  malformed calls
       |  1. Environment agreement     -- declared env must equal args env
       |  2. PolicyEngine.evaluate()    -- deny wins, else allow, else default deny
       |  3. ApprovalStore.is_approved  -- sensitive actions, exact-args token
       |  4. SecretBroker.get()         -- scoped credential for this call only
       |  5. FakeTools.dispatch()       -- the tool runs (or an MCP server, later)
       |  audit every outcome (redacted)
       |
  AuditLog (append-only, hash-chained JSONL)
```

## Modules

| Module | Responsibility | State |
|---|---|---|
| `policy.py` | Policy model (`Rule`, `Policy`), JSON loader, YAML-subset loader with strict validation (unknown fields, duplicate ids, bad effects, wrong types, duplicate keys rejected; flow collections parsed). A policy that fails to evaluate denies instead of crashing the gateway. | none |
| `engine.py` | Stateless evaluation. Deny rules first, then allow, then default deny. `explain()` returns the same decision plus steps. | none |
| `secrets.py` | `SecretBroker`: env-sourced secrets (`AGENTSHIELD_SECRET_<NAME>`), scoped per tool, default deny for unscoped secrets; all configured values registered for redaction at construction, any length. | configured secrets |
| `approval.py` | `ApprovalStore`: pending/approved requests; approval token = SHA-256 of a type-tagged canonical (tool, action, args), so changed args — or a list where a tuple was approved — produce a different token. Single-use with no replay (a consumed approval *token* can never be re-approved, though a human may grant a fresh approval for the same triple on a new request), deny revokes, 15-minute TTL (injectable clock; `None` rejected), human-only approval. | pending + approved + consumed + denied tokens |
| `budget.py` | `BudgetManager`: max calls, max seconds (injectable clock), max cost. Blocks latch once exceeded. The budget gate runs first, so every attempted call is charged — including environment-mismatched and malformed calls. `would_allow()` is the non-latching probe used by explain mode. | counters |
| `audit.py` | `AuditLog`: append-only JSONL; redacts known secrets from every free-text field before writing; entries are hash-chained and `verify()` detects flipped/reordered/deleted retained entries (except a tail rewrite with recomputed hashes) and reports corrupt lines instead of crashing, judging the chain after a corrupt line against the last valid entry. Run ids are unique per log. | file handle (append) |
| `gateway.py` | `Gateway`: the check order above; session-bound identity (`user`/`project` set at construction); `ToolCall.to_policy_call()` namespaces resources per tool (`workspace/<path>`, `<env>.<table>`, `<env>`) from the arguments the tool will consume, with `..`/`.` segments normalised first, and coerces non-string argument values to "" so they match no allow rule. `call()` and `explain()` never raise on malformed input — fields are sanitised at the gate and a safety net turns unexpected errors into denials. `explain()` evaluates the full gate (budget, policy, approval) without executing. | composed components |
| `tools.py` | `FakeTools`: files (scoped to a base dir, `realpath` symlink/containment checked; non-string paths and non-UTF-8 files are `ToolError`, never crashes), a two-environment fake DB (returns rows with `authenticated: False` when no credential is configured — the credential does not gate data access), deploy. `TOOL_COSTS` prices each action. | workspace dir, fake DB |

## Check order rationale

Budget first (a run that has spent its budget stops immediately; every
attempt that passes the check is charged — including environment-
mismatched and malformed calls, so no denial path can be looped for
free). Environment agreement second (a call whose declared environment
differs from the arguments the tool will consume is denied before
policy is evaluated — policy must never be checked on one environment
while the tool runs against another). Policy third:
authorization never depends on the model's wording. Approval fourth: only
policy-allowed sensitive actions reach a human. Secrets last: a credential
is fetched only for a call that has already passed every other gate.

## Policy evaluation semantics

- A rule matches when **every** specified field glob-matches the call.
  Unspecified fields match anything.
- Any matching `deny` rule denies (first match named in the reason).
- Otherwise any matching `allow` rule allows.
- Otherwise **default deny**, with the reason saying so explicitly.
- `explain()` evaluates the full gate (budget probe, policy, approval
  peek) through the same checks `call()` performs — the explanation
  cannot drift from the enforcement — without executing, charging
  budget, or consuming an approval.

## Resource namespacing

Tool calls carry raw args; the gateway converts them into policy resources:

- `files` → `workspace/<path>` (absolute paths stay absolute and never
  match the workspace glob — they are denied, and the tool itself also
  rejects paths escaping the base directory as defense in depth).
  `..`/`.` segments are collapsed first, so `workspace/../secret.txt`
  becomes `secret.txt` and matches no workspace rule. Symlinks are
  resolved with `realpath` before the containment check.
- `db` → `<environment>.<table>` (e.g. `staging.users`), where the
  environment is taken from the call's arguments — the value the tool
  will consume.
- `deploy` → `<environment>`, likewise from the arguments.

## Data flow for one call

```
ToolCall -> budget check -> budget.record(cost)
         -> environment agreement -> policy decision -> approval check
         -> secret fetch (db only, scoped) -> tool dispatch
         -> audit.record(redacted)
```

Every exit path — budget block, policy deny, approval refusal, tool error,
success — writes exactly one audit record.

## What is deliberately not built here

- MCP transport (the proxy adapter is milestone M1 in the blueprint).
- Persistence: policy/approvals are in-memory; audit is a local file.
- Multi-user identity (OAuth/OIDC) and a hosted control plane.
- Sandboxing: the gateway is a policy layer, not a sandbox. A local
  process has the user's own permissions (see THREAT_MODEL.md).
