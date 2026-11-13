# Changelog

All notable changes to AgentShield will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once it leaves 0.x. Until then, minor-version bumps may include breaking
changes to the policy format or CLI, and those will be called out here.

## [0.1.2] — 2026-11-11

Robustness-fix release: a second independent re-audit confirmed all
16 fixes from 0.1.1 hold, but found 10 new breaks — mostly the
gateway crashing on malformed input it is documented to survive.
All 10 are fixed here, each with a regression test in
`tests/test_round2_fixes.py` (the suite grows 145 → 183 tests). **The
package is still a reference implementation, not production-secure**
— see [THREAT_MODEL.md](THREAT_MODEL.md).

### Fixed

- **Crash on malformed input (most serious).** `Gateway.call()` is
  documented to never raise, but it raised on non-string file paths
  (`123`, `None`, `["x"]`, `{"a": 1}`, `("x",)`, `3.14`, `True` —
  `AttributeError` on `path.startswith`), `args=None` or a string
  (`AttributeError` on `.get`), unhashable db arguments
  (`TypeError` on a list/dict environment or table), binary files
  with invalid UTF-8 (`UnicodeDecodeError`, only `ToolError` was
  caught), and non-serialisable actors (`TypeError` in
  `json.dumps`). `ToolCall.to_policy_call()` and `FakeTools.dispatch`
  now validate/coerce argument types (deny, never raise),
  `files_read`/`files_list`/`files_delete`/`db_query` catch
  `OSError`/`UnicodeDecodeError` as `ToolError`, and `audit.record()`
  coerces unserialisable fields to `str`. Both `call()` and
  `explain()` have a last-resort safety net that turns any unexpected
  exception into an audited denial. The fuzz tests now generate
  non-string/malformed arguments (200 seeded trials) so "never
  raises" is actually tested.
- **Secret leak via audit actor/tool/action.** `audit.record()`
  redacted only `resource` and `detail`; a secret pasted into the
  actor, tool, or action field landed verbatim in `audit.jsonl`. All
  free-text fields are now redacted.
- **verify() tamper masking.** Flipping the last entry, recomputing
  its hash, and corrupting the penultimate line made `verify()`
  report only the corrupt line — the tamper was masked because a
  corrupt line reset the expected chain to `None`. `verify()` now
  judges the chain after a corrupt/non-object line against the last
  *valid* entry's hash, so the following entry is flagged as
  unverifiable.
- **YAML anchors/aliases silently misparsed.** `name: &a x` parsed as
  the literal string `"&a x"` and `tool: *x` became the glob `"*x"`.
  The YAML-subset parser now rejects unquoted `&`/`*`/`!` tokens,
  block scalars (`|`/`>`), and document markers (`---`/`...`) with
  `PolicyError`. Quoted `'*'` still parses as a legal glob.
- **YAML deep nesting.** ~2000 levels of nesting raised
  `RecursionError`, not `PolicyError`. The parser enforces a maximum
  nesting depth of 32.
- **Approval token collision.** `json.dumps(default=str)` made
  `{"x": [1, 2]}` and `{"x": (1, 2)}` produce the identical token.
  The canonical form is now type-tagged (list vs tuple, int vs
  string keys are distinct), and `approval_token` raises `TypeError`
  for non-string tool/action or non-JSON argument values.
- **ApprovalStore(ttl_seconds=None).** `timedelta(seconds=None)`
  crashed on first use. The constructor now rejects `None` (and
  zero/negative/non-numeric TTLs) with `ValueError`.
- **DB credential does not gate data access (doc fix).** `db.query`
  on staging returns rows with no secret configured
  (`authenticated: False`). That behaviour is pinned by a test; the
  fix is to the wording, not the tool: [THREAT_MODEL.md](THREAT_MODEL.md)
  now says policy is the only gate and secret scoping only controls
  credential handoff. Real deployments must authenticate in the
  tool/MCP server itself.
- **Env-mismatch denials are free (order fix).** Environment-mismatch
  denials ran before the budget check, so an agent could loop them
  without consuming budget. The budget check and charge now run
  **before** the environment agreement check: the gateway order is
  budget → environment agreement → policy → approval → secret →
  execute. Every attempted call is now charged, including
  environment-mismatched and malformed calls.

### Changed

- **Six false/imprecise claims corrected** (re-audit §4):
  - "gateway never raises" — now true for `call()`/`explain()`,
    backed by the malformed-argument fuzz tests and the safety net.
  - "credentials never appear in logs" — now "*configured*
    credentials" (plus the unconfigured-secret limit).
  - "flipping a retained entry is detected" — now the precise
    guarantee: flipping, reordering, or deleting a retained entry is
    detected *except* a tail rewrite in which the attacker also
    recomputes the affected hashes (pinned by a test asserting that
    case is undetectable from the file alone).
  - "a consumed approval can never be re-approved" — now the precise
    property: a consumed approval *token* can never be re-approved;
    a human may still grant a *fresh* approval for the same triple
    on a new request.
  - "anything outside the YAML subset raises PolicyError" — now the
    specific rejection list (anchors, aliases, tags, block scalars,
    document markers, depth > 32, duplicate keys, tabs).
  - Secret scoping described as production-data protection —
    corrected: scoping controls credential handoff; it does not gate
    data access.
- README, THREAT_MODEL.md, ARCHITECTURE.md, `docs/policy-guide.md`,
  and `docs/examples-guide.md` updated to match the fixed code.

## [0.1.1] — 2026-11-11

Security-fix release: an independent QA audit found 16 real
vulnerabilities and gaps; all 16 are fixed here, each with a
regression test in `tests/test_security_fixes.py` (the suite grows
85 → 145 tests). The three `expectedFailure` tests from 0.1.0 now
pass as normal tests. **The package is still a reference
implementation, not production-secure** — see
[THREAT_MODEL.md](THREAT_MODEL.md).

### Fixed

- **Environment confusion (most serious).** The gateway checked
  policy on the call's declared environment while the tool executed
  against the environment in its arguments, so a `staging` call
  carrying `prod` arguments returned full production data. The
  environment and resource are now derived from the arguments the
  tool will consume, and a declared/argument mismatch is denied
  outright before anything is evaluated.
- **Symlink escape.** `_safe_path` used lexical `abspath`; a symlink
  inside the workspace pointing outside it was followed. It now uses
  `realpath` and re-checks containment on the resolved path. File
  resources are also normalised before policy matching, so
  `workspace/../secret.txt` resolves to `secret.txt` and matches no
  workspace rule.
- **Approvals.** Approvals now expire (15-minute default, configurable,
  injectable clock), are single-use with no replay (a consumed token
  can never be re-approved), `deny()` revokes a granted approval, and
  only a human may grant one (`approve()` refuses `actor="agent"`;
  the gateway exposes no approve method at all). Granted approvals
  record `actor="human"`.
- **Redaction gaps.** Every configured secret is registered for
  redaction at broker construction — fetched or not, any length (the
  <4-character exemption is gone) — and a secret with no
  `secret_scopes` entry is handed to no tool (default deny).
- **Budgets.** Every attempted call is charged once it passes the
  budget check; denied and erroring calls can no longer loop for free.
- **YAML misparses.** The YAML-subset parser now parses flow
  collections (`[a, b]`, `{k: v}`) instead of leaving them as strings
  that `list()` would explode into characters, and duplicate mapping
  keys are rejected with a clear error.
- **Audit verify.** `verify()` no longer crashes on a corrupt line —
  it reports it and keeps checking. Entries are hash-chained, so
  flipping, reordering, or deleting a retained entry is detected.
  (Deleting the tail or the whole file is still undetectable from the
  file alone.)
- **Policy type validation.** `Policy.from_dict` / `Rule.from_dict`
  strictly validate types: a bare string for `sensitive_actions` or
  a `secret_scopes` value, a list where a string glob belongs, or a
  non-number budget is now a clear `PolicyError` instead of silently
  disabling a control. A policy that fails to evaluate denies the
  call instead of crashing the gateway.
- **Explain mode.** `Gateway.explain` now evaluates the full gate
  (budget probe, policy, approval peek) instead of policy alone, so
  it no longer reports ALLOWED for an unapproved delete or a
  budget-exhausted call — and still consumes nothing.
- **Console script.** The demo moved into the package
  (`agentshield/demo.py`); `agentshield demo` works as an installed
  console script, and CLI paths default to the repository root, so
  the CLI works from any working directory.
- **`.gitignore`** now covers `*.egg-info/` and `build/`.
- **Session identity.** `user`/`project` are bound to the gateway
  session at construction; per-call identity fields are
  caller-controlled and ignored for policy evaluation.
- **Run ids** are unique per audit log (`run_<16 hex>`) instead of
  the constant `run-1`.
- **Demo** no longer deletes `audit.jsonl` at start (append-only is
  honoured).
- **Fuzz tests** added: seeded random policies and calls assert the
  gateway never raises and deny-by-default always holds.

### Changed

- `BudgetManager` gains `would_allow()` (non-latching budget probe
  for explain mode). `ApprovalStore` gains a TTL/clock, `has_approval()`
  (non-consuming peek), and consumed/denied token sets. `AuditLog`
  gains hash-chained entries and a tolerant `verify()`. `Gateway`
  gains session identity (`user`, `project`) and the environment
  agreement check. `SecretBroker` denies unscoped secrets by default.
- The budget example and policy guide now state the per-attempt
  charging rule correctly. README, THREAT_MODEL.md, ARCHITECTURE.md,
  and docs were updated to match the fixed code.

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
