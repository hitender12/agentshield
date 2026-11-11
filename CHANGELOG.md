# Changelog

All notable changes to AgentShield will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once it leaves 0.x. Until then, minor-version bumps may include breaking
changes to the policy format or CLI, and those will be called out here.

## [0.1.0] — 2026-11-11

Initial release: a Python 3.10+ standard-library-only reference
implementation of the permission gateway described in the project
blueprint. It is **not** production-secure and has **not** been
independently reviewed — see [THREAT_MODEL.md](THREAT_MODEL.md) and
[SECURITY.md](SECURITY.md).

### Added

- **Policy engine** (`agentshield/policy.py`, `agentshield/engine.py`):
  policy-as-code with readable allow/deny rules over `tool`, `action`,
  `resource`, `environment`, `user`, and `project`; glob matching
  (`*`, `?`); strict validation that rejects unknown fields, duplicate
  rule ids, and invalid effects with `PolicyError`. Policies load from
  JSON or from a small, documented YAML subset (not a full YAML parser).
- **Default deny** (`agentshield/engine.py`): deny rules win over allow
  rules, and any call matching no rule is denied explicitly — unknown
  tools and unconfigured actions are never silently allowed.
- **Explain mode**: `PolicyEngine.explain()` / `agentshield explain`
  returns the same decision the gateway would enforce, with the
  matching rule and evaluation steps, without executing the call,
  writing an audit entry, or consuming budget.
- **Scoped secrets** (`agentshield/secrets.py`): `SecretBroker` hands a
  credential from `AGENTSHIELD_SECRET_<NAME>` to a single tool only
  when that tool is listed in the policy's `secret_scopes`; credentials
  never appear in prompts, logs, or tool arguments visible to the model.
- **Human approvals** (`agentshield/approval.py`): sensitive actions
  require an explicit approval bound to the exact (tool, action, args)
  triple (SHA-256 token), so changing the arguments invalidates the
  approval. Approvals are single-use.
- **Budgets and quotas** (`agentshield/budget.py`): per-run call-count,
  wall-clock-time, and cost ceilings (`max_calls`, `max_seconds`,
  `max_cost`). Exceeding any budget latches the block; only executed
  calls are charged.
- **Audit log** (`agentshield/audit.py`): append-only JSONL records of
  actor, tool, action, resource, policy decision, timestamp, and
  outcome — including denials — with known secret values redacted
  before writing (`[REDACTED:<NAME>]`). `verify()` checks the file is
  intact JSONL with all required fields.
- **Gateway** (`agentshield/gateway.py`): routes each tool call through
  budget → policy → approval → secret scoping → execution, in that
  order, auditing every outcome. Resources are namespaced per tool
  (`files` → `workspace/<path>`, `db` → `<environment>.<table>`,
  `deploy` → `<environment>`).
- **Demo** (`demo.py`, `python -m agentshield demo`): a scripted run
  over local fake tools (`agentshield/tools.py` — a workspace-scoped
  file tool, a staging/production fake database, and deploy) showing
  allowed reads, a denied forbidden path, staging allowed vs
  production denied, approval-gated delete, approval invalidation on
  changed arguments, default deny of an unknown tool, explain mode,
  budget enforcement, and a redacted audit log.
- **Example policies** (`policies/examples/`, each in JSON and
  equivalent YAML-subset forms): `demo-policy` (7 rules,
  `delete`/`run`/`send`/`buy` sensitive actions, 50-call /
  300-second / $5.00 budgets, `DB_PASSWORD` scoped to `db` only);
  `strict-readonly` (9 rules — workspace list/read, staging DB
  read, and explicit denies for write, delete, deploy, shell, and
  prod DB; 20-call / $1.00 budgets); `team-policy` (9 rules —
  staging allow / prod deny for DB, deploy, and delete, plus an
  `issues.read` rule scoped to project `team-alpha`; 100-call /
  600-second / $10.00 budgets).
- **Tests**: 85 tests (`python -m unittest discover -s tests`),
  including a 9-case policy decision table, staging-vs-prod, approval
  binding and single-use, budget call/cost/time enforcement, secret
  scoping and audit redaction, and explain-mode correctness — plus
  edge-case tests (policy decision table, approval expiry, budget
  boundaries, path-escape attempts, YAML-subset limits) and tests
  enforcing the example policies in `policies/examples/`. 3 tests are
  marked `expectedFailure`: they document spec-required behaviour the
  reference core does not yet implement (approval expiry, symlink
  escape from the workspace).
- **Documentation**: README quickstart, `ARCHITECTURE.md` (component
  boundaries and check-order rationale), `THREAT_MODEL.md` (assets,
  assumptions, and what the gateway does *not* protect against),
  `SECURITY.md` (vulnerability reporting), `CONTRIBUTING.md`,
  `CODE_OF_CONDUCT.md`, and `docs/policy-guide.md` /
  `docs/examples-guide.md`.
- **CLI** (`agentshield/__main__.py`): `demo`, `explain`, and `check`
  subcommands.

### Known limitations

- No real MCP transport; the demo routes to local fake tools. An MCP
  proxy adapter is the next milestone (M1 in the blueprint roadmap).
- Policy and approvals live in memory; restarting loses pending
  approvals. The audit log is a local JSONL file with no cryptographic
  tamper evidence (`verify()` checks structure, not authenticity).
- The YAML reader is a documented subset, not full YAML.
- Cost accounting uses static per-tool prices, not measured spend.
- A local process has the user's own permissions: the gateway cannot
  protect against a fully compromised host. See `THREAT_MODEL.md`.
