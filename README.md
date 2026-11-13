# AgentShield — a permission gateway for AI tools and MCP servers

> **One auditable permission and policy layer in front of AI tools and MCP servers.** Put AgentShield between an agent and its tools, and define what the agent may do in readable policy — outside the model's reasoning loop.

A prompt saying "do not delete files" is not an access-control mechanism. AgentShield enforces allow/deny rules, scoped credentials, human approval, budgets, and an audit trail in a gateway the model cannot talk its way past.

**Status: reference implementation, not production-secure.** See [THREAT_MODEL.md](THREAT_MODEL.md) and [SECURITY.md](SECURITY.md). Do not label it production-secure until it has been independently reviewed.

## Quickstart

```bash
python demo.py                    # scripted demo: allowed vs blocked calls
python -m agentshield demo        # same demo via the CLI
python -m agentshield explain --policy policies/examples/demo-policy.json \
    --tool db --action query --resource prod.users --environment prod
python -m agentshield check --policy policies/examples/demo-policy.yaml
python -m unittest discover -s tests
```

Python 3.10+, standard library only. No network calls, no keys, no installs.

## What the demo shows

```
[ALLOWED] files.list workspace        allowed by policy
[ALLOWED] files.read notes.txt        allowed by policy
[DENIED ] files.read /etc/passwd      Denied by default: no allow rule matches
[ALLOWED] db.query staging.users      allowed by policy
[DENIED ] db.query prod.users         Denied by rule 'deny-db-prod'
[DENIED ] files.delete notes.txt      approval required for sensitive action
[ALLOWED] files.delete notes.txt      allowed by policy  (after human approval)
[DENIED ] files.delete other.txt      approval required  (args changed: approval invalid)
[DENIED ] shell.exec 'rm -rf /'       Denied by default: no allow rule matches
```

## How it works

1. **Policy-as-code** — readable rules for tools, users, projects, environments, resources, and actions. Policies load from JSON, or from a small documented YAML subset (see `agentshield/policy.py`; it is not a full YAML parser). Policies are strictly validated: bad types are rejected with a clear error instead of silently disabling a control, and a policy that fails to evaluate denies the call instead of crashing the gateway.
2. **Default deny** — unknown tools and unconfigured actions are denied, never silently allowed. Deny rules win over allow rules. For database and deploy calls, the environment and resource are derived from the arguments the tool will actually consume, and a call whose declared environment disagrees with its arguments is denied outright. File resources are normalised first, so a `workspace/../secret.txt` traversal cannot slip through a `workspace/*` rule. Identity (`user`/`project`) is bound to the gateway session at construction — per-call identity fields are caller-controlled and ignored.
3. **Scoped secrets** — the broker hands a credential from `AGENTSHIELD_SECRET_<NAME>` to the single action that needs it, only when that tool is in the secret's scope. A secret with no scope entry is handed to *no* tool (default deny). Every configured secret is registered for redaction at startup — fetched or not, any length — so *configured* credentials never appear in prompts, logs, or tool arguments visible to the model. A secret the broker was never configured with cannot be redacted. Secret scoping controls credential *handoff* only: it does not gate data access — the demo database returns rows with `authenticated: False` when no credential is configured, and policy is the only gate on what the agent may read.
4. **Human approval** — sensitive operations (`delete`, `deploy`, `send`, `buy`) require an explicit approval showing the exact action and arguments. Changing the arguments invalidates the approval, and approvals are single-use: a consumed approval *token* can never be re-approved or replayed — though a human may grant a *fresh* approval for the same (tool, action, args) if a new request is made. Denying an approval revokes it. Approvals expire (15-minute default, configurable). Only a human may grant one — the gateway exposes no approve method, so the agent cannot approve its own calls.
5. **Budgets and quotas** — per-run tool-call count, time limit, and cost ceiling. Exceeding any blocks further calls (the block latches). The budget gate runs *first*, so every *attempted* call is charged — including environment-mismatched and malformed calls — and denied and erroring calls cannot loop for free.
6. **Audit log** — append-only JSONL records (actor, tool, policy decision, resource, timestamp, outcome) with configured secrets redacted from *every* free-text field before writing. Entries are hash-chained, so flipping, reordering, or deleting a retained entry is detected by `verify()` — except a tail rewrite in which the attacker also recomputes the affected hashes, which is undetectable from the file alone (same limit as tail deletion; ship the log to remote storage for that).
7. **Explain mode** — ask why an action would be allowed or denied without executing it: `agentshield explain ...`. Explain evaluates the full gate (budget, policy, approval) exactly as `call` would, without consuming budget or an approval.

## Policy example

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

Rule fields support glob patterns (`*`, `?`). A rule with no field set for a dimension matches any value on that dimension.

## Repository layout

```text
agentshield/            # reference gateway package
  policy.py             # policy model + JSON/YAML-subset loaders
  engine.py             # allow/deny evaluation + explain mode
  secrets.py            # scoped secret broker + redaction
  approval.py           # exact-action approvals (args-bound tokens)
  budget.py             # call/time/cost budgets
  audit.py              # append-only hash-chained JSONL audit log
  gateway.py            # the gateway: budget -> env check -> policy -> approval -> tool
  demo.py               # scripted demo gateway run (also the CLI's demo)
  tools.py              # fake tools (files, db, deploy) for the demo
  __main__.py           # CLI: demo / explain / check
policies/examples/      # demo policy in JSON and YAML-subset forms
demo.py                 # thin entry point: `python demo.py`
demo-workspace/         # files the demo tools may touch
tests/                  # 183 tests incl. decision tables, security regressions, fuzz
THREAT_MODEL.md         # what this does and does not protect against
SECURITY.md             # vulnerability reporting
```

## Measured results

`python -m unittest discover -s tests` — **183 tests, OK**. Coverage includes a 25-case policy decision table (allow/deny/default-deny), staging-vs-prod, approval binding, single-use, expiry, revocation and human-only approval, budget call/cost/time enforcement with per-attempt charging (including environment-mismatched and malformed calls), secret scoping and audit redaction (all free-text fields), hash-chain tamper detection (including the flip-after-corrupt-line case), environment-mismatch rejection, symlink-escape blocking, YAML flow collections, duplicate-key, anchor/alias/tag and depth-limit rejection, type-distinct approval tokens, full-gate explain-mode correctness, and seeded fuzz tests over random policies and calls (300 random policies × 10 random calls, plus 200 malformed-argument trials, asserting the gateway never raises and deny-by-default always holds). The demo's audit log verifies clean (`verify()` reports 0 problems) and contains no secret value.

## Honest limits

- **Python reference implementation, not the production system.** The blueprint's production stack is a Rust daemon (Tokio/Axum) plus a TypeScript MCP adapter; this package mirrors that design so the port is mechanical, but it is not that system.
- **No real MCP transport.** The demo routes to local fake tools. An MCP proxy adapter is the next milestone.
- **No persistence.** Policy and approvals live in memory; the audit log is a local JSONL file.
- **Local-process trust boundary.** A local process has the user's own permissions; this gateway cannot protect against a fully compromised host. See THREAT_MODEL.md.
- **The YAML reader is a subset**, documented in `policy.py`: it parses flow collections (`[a, b]`, `{k: v}`) and rejects duplicate keys, anchors, aliases, tags, block scalars, document markers, and nesting beyond 32 levels with `PolicyError` — but it is still not full YAML. Use JSON for complex policies.
- **Audit tamper evidence is hash-chained, not signed.** Editing, reordering, or deleting a retained entry is detected by `verify()` — except a tail rewrite in which the attacker also recomputes the affected hashes; deleting the tail of the log or the whole file is likewise not detectable from the file alone — ship the log to remote storage for that.
- **Not production-secure until independently reviewed.** See SECURITY.md.

## Roadmap (from the blueprint)

M1 proxy one MCP server · M2 allowlist/denylist + default deny ✓ (reference) · M3 per-tool scoped rules + explain mode ✓ (reference) · M4 exact-action approvals ✓ (reference) · M5 redaction, quotas, audit log ✓ (reference) · M6 threat model, pen-test scope, conformance tests, Docker deployment.
