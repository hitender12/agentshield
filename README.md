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

1. **Policy-as-code** — readable rules for tools, users, projects, environments, resources, and actions. Policies load from JSON, or from a small documented YAML subset (see `agentshield/policy.py`; it is not a full YAML parser).
2. **Default deny** — unknown tools and unconfigured actions are denied, never silently allowed. Deny rules win over allow rules.
3. **Scoped secrets** — the broker hands a credential from `AGENTSHIELD_SECRET_<NAME>` to the single action that needs it, only when that tool is in the secret's scope. Credentials never appear in prompts, logs, or tool arguments visible to the model.
4. **Human approval** — sensitive operations (`delete`, `deploy`, `send`, `buy`) require an explicit approval showing the exact action and arguments. Changing the arguments invalidates the approval, and approvals are single-use.
5. **Budgets and quotas** — per-run tool-call count, time limit, and cost ceiling. Exceeding any blocks further calls (the block latches).
6. **Audit log** — append-only JSONL records (actor, tool, policy decision, resource, timestamp, outcome) with configured secrets redacted before writing.
7. **Explain mode** — ask why an action would be allowed or denied without executing it: `agentshield explain ...`.

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
  audit.py              # append-only redacted JSONL audit log
  gateway.py            # the gateway: policy -> approval -> budget -> tool
  tools.py              # fake tools (files, db, deploy) for the demo
  __main__.py           # CLI: demo / explain / check
policies/examples/      # demo policy in JSON and YAML-subset forms
demo.py                 # scripted demo gateway run
demo-workspace/         # files the demo tools may touch
tests/                  # 29 tests incl. a policy decision table
THREAT_MODEL.md         # what this does and does not protect against
SECURITY.md             # vulnerability reporting
```

## Measured results

`python -m unittest discover -s tests` — **29 tests, OK**. Coverage includes a 9-case policy decision table (allow/deny/default-deny), staging-vs-prod, approval binding and single-use, budget call/cost/time enforcement, secret scoping and audit redaction, and explain-mode correctness. The demo's audit log verifies clean (`verify()` reports 0 problems) and contains no secret value.

## Honest limits

- **Python reference implementation, not the production system.** The blueprint's production stack is a Rust daemon (Tokio/Axum) plus a TypeScript MCP adapter; this package mirrors that design so the port is mechanical, but it is not that system.
- **No real MCP transport.** The demo routes to local fake tools. An MCP proxy adapter is the next milestone.
- **No persistence.** Policy and approvals live in memory; the audit log is a local JSONL file.
- **Local-process trust boundary.** A local process has the user's own permissions; this gateway cannot protect against a fully compromised host. See THREAT_MODEL.md.
- **The YAML reader is a subset**, documented in `policy.py`. Use JSON for complex policies.
- **Not production-secure until independently reviewed.** See SECURITY.md.

## Roadmap (from the blueprint)

M1 proxy one MCP server · M2 allowlist/denylist + default deny ✓ (reference) · M3 per-tool scoped rules + explain mode ✓ (reference) · M4 exact-action approvals ✓ (reference) · M5 redaction, quotas, audit log ✓ (reference) · M6 threat model, pen-test scope, conformance tests, Docker deployment.
