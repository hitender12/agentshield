# Policy Guide

How to write AgentShield policies: rules, glob matching, deny-wins,
environments, approvals, budgets, and worked examples.

This guide is about *authoring* policies. For how policies are
evaluated inside the gateway, see [ARCHITECTURE.md](../ARCHITECTURE.md)
("Policy evaluation semantics" and "Check order rationale"); for what
the gateway does and does not protect against, see
[THREAT_MODEL.md](../THREAT_MODEL.md).

## The one idea

A policy is a human-written list of what an agent may do. The gateway
evaluates it for every tool call, outside the model's reasoning loop.
A prompt saying "do not delete files" is not access control; a policy
rule that denies `files.delete` is.

## Anatomy of a policy

```json
{
  "name": "demo",
  "version": 1,
  "sensitive_actions": ["delete", "run", "send", "buy"],
  "budgets": {"max_calls": 50, "max_seconds": 300, "max_cost": 5.0},
  "secret_scopes": {"DB_PASSWORD": ["db"]},
  "rules": [
    {"id": "allow-db-staging", "effect": "allow",
     "tool": "db", "action": "query",
     "resource": "staging.*", "environment": "staging"},
    {"id": "deny-db-prod", "effect": "deny",
     "tool": "db", "action": "query",
     "resource": "prod.*", "environment": "prod"}
  ]
}
```

| Field | Required | Meaning |
| ----- | -------- | ------- |
| `name` | No (default `"unnamed"`) | Human-readable policy name. Shown by `agentshield check`. |
| `version` | No (default `1`) | Policy version. Bump it when the rules change so an audit record can be tied to the policy that produced it. |
| `rules` | **Yes** | The allow/deny rules. Must be a list; each rule needs a unique `id` and an `effect`. |
| `sensitive_actions` | No | Actions that need a human approval even when a rule allows them (see [Approvals](#approvals)). |
| `budgets` | No | Per-run ceilings: `max_calls`, `max_seconds`, `max_cost` (see [Budgets](#budgets)). |
| `secret_scopes` | No | `{SECRET_NAME: [tool, ...]}` — which tools may receive each credential (see [Scoped secrets](#scoped-secrets)). |

The loader (`agentshield/policy.py`, `Policy.from_dict`) rejects a
policy with unknown rule fields, duplicate rule ids, or an effect
other than `allow`/`deny`, raising `PolicyError`. It fails loudly on
malformed input rather than guessing — validate with
`python -m agentshield check --policy <file>` before deploying a policy.

## Rules

A rule has an `id`, an `effect`, and any subset of six match fields:

| Field | What it matches |
| ----- | --------------- |
| `tool` | The tool name, e.g. `files`, `db`, `deploy`, `shell`. |
| `action` | The action on that tool, e.g. `read`, `query`, `run`, `exec`. |
| `resource` | The resource, namespaced per tool by the gateway (see below). |
| `environment` | The environment of the call, e.g. `staging`, `prod`. |
| `user` | The user the call is attributed to. |
| `project` | The project the call belongs to. |

**A field you omit matches anything on that dimension.** A rule with
only `tool: db` matches every `db` call in every environment. Treat
every omission as a conscious choice: scope narrowly first, then widen
deliberately.

A rule matches a call only when **every** specified field matches.
Rule ids must be unique within a policy, and should be stable and
descriptive (`allow-db-staging`, `deny-db-prod`) — they appear in
audit records and denial reasons, so renaming one breaks anyone
grepping logs for it.

### Glob matching

Match fields are glob patterns, evaluated case-sensitively with
Python's `fnmatch.fnmatchcase`:

- `*` matches any sequence of characters, including `/` and `.`.
- `?` matches exactly one character.
- Anything else matches literally.

Examples:

| Pattern | Matches | Does not match |
| ------- | ------- | -------------- |
| `workspace/*` | `workspace/notes.txt`, `workspace/sub/dir/file` | `/etc/passwd`, `workspace` |
| `staging.*` | `staging.users`, `staging.orders` | `prod.users`, `staging` |
| `prod.*` | `prod.users` | `staging.users` |
| `db` | `db` | `db2` |
| `*.txt` | `notes.txt` | `notes.md` |

Because `*` crosses `/`, `workspace/*` is broad — it covers nested
directories too. If you need to confine reads to one directory level,
there is no such pattern in this engine; say so in a review rather
than assuming the glob is narrower than it is. The file tool itself
also rejects paths escaping its base directory, as defence in depth
(see `agentshield/tools.py`, `_safe_path`).

### Resource namespacing

Tool calls carry raw arguments; the gateway converts them into the
`resource` a rule sees (`ToolCall.to_policy_call()` in
`agentshield/gateway.py`):

| Tool | Resource | Example |
| ---- | -------- | ------- |
| `files` | `workspace/<path>` — absolute paths stay absolute | `files.read notes.txt` → `workspace/notes.txt`; `files.read /etc/passwd` → `/etc/passwd` |
| `db` | `<environment>.<table>` | `db.query` staging `users` → `staging.users` |
| `deploy` | `<environment>` | `deploy.run` prod → `prod` |
| anything else | first of `path`, `table`, `environment` args, else `""` | `shell.exec` → `""` |

This is why an absolute path can never match a `workspace/*` rule:
it never becomes a workspace resource in the first place, so it is
denied — and the tool rejects it again on its own. Write rules against
these namespaced resources, not against raw arguments.

### Deny-wins and default deny

Evaluation order (`agentshield/engine.py`, `PolicyEngine.evaluate`):

1. **Any matching `deny` rule denies**, naming the first matching
   deny rule in the reason (`Denied by rule 'deny-db-prod'`).
2. Otherwise, **any matching `allow` rule allows**, naming the rule
   (`Allowed by rule 'allow-db-staging'`).
3. Otherwise, **default deny** — the call is denied with a reason
   saying so explicitly (`Denied by default: no allow rule matches`).

Two consequences to internalise:

- **Deny wins over allow.** If both an allow rule and a deny rule
  match the same call, the call is denied. This is what makes
  "allow staging, deny prod" safe to write as two rules instead of
  one complicated rule.
- **Silence is a denial.** An unknown tool (`shell`), an unconfigured
  action (`files.write` in the demo policy), or a resource no rule
  covers is denied — never silently allowed. If a call you expected
  to work is denied, the first thing to check is whether any allow
  rule actually matches it; `explain` (below) shows you.

Deny the dangerous thing **explicitly** anyway. Default deny is the
backstop, but a named deny rule shows up in the audit reason and in
`explain` output, so a reviewer can see *why* a call was refused
instead of guessing.

### Explain mode

Ask why a call would be allowed or denied **without executing it**:

```bash
python -m agentshield explain --policy policies/examples/demo-policy.json \
    --tool db --action query --resource prod.users --environment prod
```

Output:

```text
allowed: False
reason:  Denied by rule 'deny-db-prod'
  - deny rule matched: deny-db-prod [deny] tool=db, action=query, resource=prod.*, environment=prod
```

`explain` runs the identical code path as `evaluate`, so the
explanation cannot drift from the enforcement — and it never executes
the call, writes an audit entry, or consumes budget (there is a test
for that: `test_explain_mode_gives_correct_reason`). Use it every
time you write or change a policy, before trusting it. Exit code 0
means allowed, 1 means denied.

## Environments: staging vs production

Environments are the most common policy axis, and the demo policy
shows the intended pattern — allow in staging, explicitly deny in
production, for both data access and deploys:

```json
{"id": "allow-db-staging", "effect": "allow",
 "tool": "db", "action": "query",
 "resource": "staging.*", "environment": "staging"},
{"id": "deny-db-prod", "effect": "deny",
 "tool": "db", "action": "query",
 "resource": "prod.*", "environment": "prod"},
{"id": "allow-deploy-staging", "effect": "allow",
 "tool": "deploy", "action": "run",
 "resource": "staging", "environment": "staging"},
{"id": "deny-deploy-prod", "effect": "deny",
 "tool": "deploy", "action": "run",
 "resource": "prod", "environment": "prod"}
```

Notes:

- Match **both** `resource` and `environment`. The resource
  (`staging.users`) already encodes the environment, but matching
  both makes the intent explicit and keeps the rule correct if
  resource namespacing ever changes.
- An allow rule scoped to `environment: staging` does not, by itself,
  protect production — it is the deny rule (plus default deny) that
  does. Write the deny rule. A policy with only
  `allow-db-staging` and no `deny-db-prod` still blocks prod by
  default, but nothing in the audit log says *why*.
- `ToolCall.environment` defaults to `"staging"`. A caller that
  forgets to set the environment gets staging rules applied to it —
  which is safe only because staging rules are the narrow ones. When
  you add a real tool, set the environment explicitly at the call
  site and test the prod case (the decision table does exactly this).

## Approvals

`sensitive_actions` lists actions that need a human approval even
when a policy rule allows them. The demo policy names `delete`,
`run`, `send`, and `buy` — the irreversible or money-spending
actions. The gateway check order is budget → policy → approval →
secret → execute, so only a policy-allowed sensitive action ever
reaches a human.

How approvals work (`agentshield/approval.py`):

- `Gateway.request_approval(call)` returns a token for the exact
  (tool, action, args) triple — the token is the SHA-256 of the
  canonical JSON of that triple.
- A human approves the token after seeing the exact action and
  arguments. Rubber-stamping an approval without reading it protects
  nothing (threat-model assumption 5).
- At execution time the gateway recomputes the token from the
  **actual** call. Different arguments produce a different token, so
  an approval for `files.delete notes.txt` does not cover
  `files.delete other.txt`, and an approval for deploying service
  `web` does not cover deploying service `api`.
- Approvals are **single-use**: once the approved call has run, the
  same approval cannot be used again.

Policy consequences:

- Listing an action in `sensitive_actions` without an allow rule
  changes nothing — the call is denied by policy before approval is
  ever considered.
- An approval **never overrides a policy denial**. Approving a prod
  deploy does not make it run; `deny-deploy-prod` still denies it.
  (Demonstrated in `examples/deploy-approval/`.)
- Keep `sensitive_actions` short. Every action in the list adds a
  human step to the agent's loop; reserve it for actions that are
  irreversible, externally visible, or spend money.

## Budgets

`budgets` caps a single run (one `BudgetManager`, one gateway):

```json
"budgets": {"max_calls": 50, "max_seconds": 300, "max_cost": 5.0}
```

| Key | Meaning |
| --- | ------- |
| `max_calls` | Maximum number of executed tool calls in the run. |
| `max_seconds` | Maximum wall-clock seconds since the run started. |
| `max_cost` | Maximum total cost, in the currency of the per-tool price table (`TOOL_COSTS` in `agentshield/tools.py`: `files.list` $0.00, `files.read` $0.01, `files.delete` $0.05, `db.query` $0.02, `deploy.run` $0.50). |

Rules of the budget system (`agentshield/budget.py`):

- **Exceeding any budget blocks everything**, and the block
  **latches** — once blocked, later calls stay blocked for the rest
  of the run.
- **Only executed calls are charged.** A call denied by policy or
  refused for lack of approval is never charged, so a run that hits
  its budget stopped on real work, not on denials.
- Omit a key to leave that dimension uncapped. All three omitted
  means no budget at all — do not do that for an agent you do not
  fully trust.
- Costs here are static per-tool prices, not measured spend. They
  are a runaway-loop guard, not a billing system.

Set budgets from the blast radius you can tolerate: how many calls,
how much time, and how much (nominal) spend before a human should
look at what the agent is doing.

## Scoped secrets

`secret_scopes` maps a secret name to the tools allowed to receive it:

```json
"secret_scopes": {"DB_PASSWORD": ["db"]}
```

The broker (`agentshield/secrets.py`, `SecretBroker`) reads secrets
only from the process environment, as `AGENTSHIELD_SECRET_<NAME>`
(`AGENTSHIELD_SECRET_DB_PASSWORD` for `DB_PASSWORD`), or from an
explicitly supplied mapping. It hands a value out only when the
requesting tool is in that secret's scope list — `files` asking for
`DB_PASSWORD` gets `None`.

Rules:

- **Never put a secret in a policy file.** Policy files are reviewed,
  versioned, and shared; a credential in one must be treated as
  compromised.
- Every value the broker has handed out is registered for redaction,
  so the audit writer scrubs it from recorded text as
  `[REDACTED:<NAME>]`. A secret the broker never handed out is not
  redacted — another reason to route every credential through the
  broker.
- Scoping is not secrecy from nothing: if the host or user account is
  compromised, the environment can be read directly (threat-model
  assumption 4). The broker limits *which tool* sees a credential,
  it does not protect the credential from the host.

## JSON vs the YAML subset

Policies load from JSON (`Policy.from_json_file`) or from a small
YAML subset (`Policy.from_yaml_subset_file`). The CLI picks by file
extension: `.json` → JSON, `.yaml`/`.yml` → YAML subset.

The subset (documented in the module docstring of
`agentshield/policy.py`) supports:

- `key: value` pairs (strings, ints, floats, booleans, null)
- nested mappings by indentation (spaces only — **tabs are rejected**)
- lists with `- item` and `- key: value` (list of maps)
- `#` full-line comments and ` #` trailing comments outside quotes
- single- and double-quoted strings

It is **not** a full YAML parser. Anything outside the subset raises
`PolicyError` instead of being misinterpreted. The two example
policies are equivalent by construction — there is a test proving the
JSON and YAML forms load to the same rules, budgets, scopes, and
sensitive actions (`test_yaml_subset_matches_json`).

Prefer JSON for complex policies and for anything generated by a
program. Use the YAML subset only for short, hand-written policies,
and run `agentshield check` on the result.

```yaml
# Equivalent to demo-policy.json (excerpt).
name: demo
version: 1
sensitive_actions:
  - delete
  - run
  - send
  - buy
budgets:
  max_calls: 50
  max_seconds: 300
  max_cost: 5.0
secret_scopes:
  DB_PASSWORD:
    - db
rules:
  - id: allow-db-staging
    effect: allow
    tool: db
    action: query
    resource: staging.*
    environment: staging
  - id: deny-db-prod
    effect: deny
    tool: db
    action: query
    resource: prod.*
    environment: prod
```

## Worked examples

### 1. Read-only research agent

Allow listing and reading inside the workspace, nothing else. There
is no allow rule for `write` or `delete`, so those are denied by
default — and `delete` is also listed in `sensitive_actions`, so even
a future allow rule would still need a human. This is
`examples/read-only-agent/policy.json`:

```json
{
  "name": "read-only-agent",
  "version": 1,
  "sensitive_actions": ["delete"],
  "budgets": {"max_calls": 50, "max_seconds": 300, "max_cost": 5.0},
  "secret_scopes": {},
  "rules": [
    {"id": "allow-list-workspace", "effect": "allow",
     "tool": "files", "action": "list", "resource": "workspace/*"},
    {"id": "allow-read-workspace", "effect": "allow",
     "tool": "files", "action": "read", "resource": "workspace/*"}
  ]
}
```

`files.read /etc/passwd` is denied twice over: the absolute path
never matches `workspace/*`, and there is no rule for it at all.

### 2. Staging-only deploy agent

Allow deploys to staging (with approval, since `run` is sensitive),
deny deploys to prod outright. This is
`examples/deploy-approval/policy.json`:

```json
{
  "name": "deploy-approval",
  "version": 1,
  "sensitive_actions": ["run"],
  "budgets": {"max_calls": 50, "max_seconds": 300, "max_cost": 5.0},
  "secret_scopes": {},
  "rules": [
    {"id": "allow-deploy-staging", "effect": "allow",
     "tool": "deploy", "action": "run",
     "resource": "staging", "environment": "staging"},
    {"id": "deny-deploy-prod", "effect": "deny",
     "tool": "deploy", "action": "run",
     "resource": "prod", "environment": "prod"}
  ]
}
```

Note that `deploy.run` to prod is denied **even with** a human
approval — approvals never override policy.

### 3. Scoping by user and project

Rules can also match on `user` and `project`, for example to let one
operator read a shared dataset while everyone else is denied:

```json
{"id": "allow-analyst-read-shared", "effect": "allow",
 "tool": "files", "action": "read",
 "resource": "workspace/shared/*",
 "user": "analyst", "project": "quarterly-review"}
```

Omit `user`/`project` unless you actually need them — the gateway's
`ToolCall` defaults are `user="dev"`, `project="demo"`, and a rule
that matches on a user nobody sets will silently never match. Test
with `explain` using the real actor values.

## Common mistakes

1. **An allow rule broader than intended.** An omitted field matches
   everything. `{"effect": "allow", "tool": "db"}` allows prod queries
   too — unless a deny rule covers prod, and deny-wins saves you.
   Re-read every omitted field before committing.
2. **Forgetting the deny rule.** Default deny blocks the call, but
   nobody reading the audit log learns why. Write the explicit deny.
3. **Matching raw arguments instead of namespaced resources.**
   `files.read` with `path: notes.txt` is resource
   `workspace/notes.txt`, not `notes.txt`. A rule with
   `resource: notes.txt` matches nothing.
4. **Assuming `*` stops at `/`.** It does not — `workspace/*`
   matches nested paths. The file tool's path-escape check is the
   second line of defence, not the policy.
5. **Putting a secret in the policy.** Secrets live in the
   environment and are scoped via `secret_scopes`. Never in JSON/YAML.
6. **Trusting the policy without running `explain`.** A policy that
   has never been explained against its prod case is untested.
   Add the case to the decision table too (see
   [CONTRIBUTING.md](../CONTRIBUTING.md), "How to add a policy
   decision-table test").

## Checklist before shipping a policy

- [ ] `python -m agentshield check --policy <file>` prints `OK`.
- [ ] `explain` says what you expect for the happy path **and** for
      the prod/forbidden case.
- [ ] Every dangerous action has an explicit deny rule, not just
      default deny.
- [ ] `sensitive_actions` covers every irreversible or spending action
      the policy allows.
- [ ] Budgets are set, and you know what each ceiling means for this run.
- [ ] No secret appears in the policy file.
- [ ] New behaviour is covered by a decision-table test.
- [ ] The policy's `version` was bumped if the rules changed.
