# Contributing to AgentShield

Thank you for helping make AgentShield better. This is a security-sensitive
project, so contributions are reviewed for correctness first and features
second. A small, well-tested change that preserves the default-deny
guarantee is worth far more than a large untested one.

Please read [THREAT_MODEL.md](THREAT_MODEL.md) before contributing. It
explains what AgentShield does and — just as importantly — what it does
**not** protect against. Do not submit a change that claims a security
property the threat model says the gateway does not provide.

> **Security issues are not handled here.** If you have found a
> vulnerability, do **not** open a public issue or pull request. Follow
> [SECURITY.md](SECURITY.md) instead.

## Local setup

AgentShield is a Python 3.10+ reference implementation using the
**standard library only**. There is nothing to install: no `pip install`,
no virtual environment, no network access, no API keys.

```bash
git clone <repo-url>
cd agentshield
python3 --version        # 3.10 or newer
```

That is the whole setup. If a change needs a third-party dependency,
stop and open an issue first — adding a dependency is a design decision
for this project, not a drive-by change.

## Running the tests

```bash
python -m unittest discover -s tests
```

All tests must pass before a pull request is considered ready
(`python -m unittest discover -s tests` — 85 tests at v0.1.0: 29 core
tests in `test_agentshield.py`, 43 edge-case tests in
`test_edge_cases.py`, 13 example-policy tests in
`test_example_policies.py`). The suite covers policy loading (JSON and
the YAML subset), the 9-case policy decision table, deny-wins, approval
binding and single-use, budget call/cost/time enforcement, secret
scoping and audit redaction, and explain-mode correctness. Run the
tests from the repository root; the test modules insert the repo root
on `sys.path` themselves.

Note: 3 of the 85 are marked `expectedFailure` on purpose. They
document behaviour the spec requires but the reference core does not
yet implement (approval expiry, and symlink escape from the
workspace). They are not hidden passes — do not "fix" them by
weakening the assertion; fix the core module instead.

## Running the demo

The demo is the fastest way to see the gateway end to end — allowed
reads, a denied forbidden path, staging allowed vs production denied,
a delete blocked without approval, the same delete allowed after a
human approval, an approval invalidated when the arguments change, an
unknown tool denied by default, explain mode, budget enforcement, and
a redacted audit log:

```bash
python demo.py                    # scripted demo
python -m agentshield demo        # same demo via the CLI
```

The demo is self-contained: it sets a demo-only secret in-process
(`s3cr3t-db-password-123`), recreates `demo-workspace/notes.txt` and
`data.txt` on each run, and rewrites `audit.jsonl`. It prints a
redaction check at the end — the demo secret must **not** appear in
the audit file. Never point the demo at a real workspace or a real
secret; use `AGENTSHIELD_SECRET_<NAME>` environment variables for real
credentials (see `agentshield/secrets.py`).

Two more CLI commands are useful while developing:

```bash
# Validate a policy file without running anything (exit 0 = valid).
python -m agentshield check --policy policies/examples/demo-policy.json
python -m agentshield check --policy policies/examples/demo-policy.yaml

# Ask why a call would be allowed or denied, without executing it.
# Exit 0 = allowed, exit 1 = denied.
python -m agentshield explain --policy policies/examples/demo-policy.json \
    --tool db --action query --resource prod.users --environment prod
```

`explain` must never execute the call, write an audit entry, or consume
budget. If a change makes it do any of those, it is a bug — see the
test `test_explain_mode_gives_correct_reason` in `tests/test_agentshield.py`.

## How to write a policy

Policies live in `policies/examples/` and load from JSON, or from a
small documented YAML subset. The full guide is
[docs/policy-guide.md](docs/policy-guide.md); the essentials:

- A policy is a named, versioned document: `name`, `version`, a `rules`
  list, `sensitive_actions`, `budgets`, and `secret_scopes`.
- Every rule has a unique `id` and an `effect` of `allow` or `deny`,
  plus any of `tool`, `action`, `resource`, `environment`, `user`,
  `project`. A field you omit matches anything on that dimension.
- Patterns are globs (`*` and `?`, case-sensitive, via `fnmatch`).
- **Deny wins:** any matching deny rule denies, even if an allow rule
  also matches. If no rule matches, the call is denied by default.
- Resources are namespaced per tool by the gateway (`gateway.py`,
  `ToolCall.to_policy_call()`): `files` → `workspace/<path>`,
  `db` → `<environment>.<table>`, `deploy` → `<environment>`. Absolute
  file paths stay absolute and never match the `workspace/*` glob.
- Sensitive actions (`delete`, `run`, `send`, `buy` in the demo policy)
  need a human approval bound to the exact arguments, even when a rule
  allows them. Changing the arguments invalidates the approval, and
  approvals are single-use.
- Budgets (`max_calls`, `max_seconds`, `max_cost`) cap a run. Once a
  budget is exceeded the block latches — later calls stay blocked.
  Only executed calls are charged; denied or unapproved calls cost
  nothing.

JSON example (from `policies/examples/demo-policy.json`):

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

The YAML subset is documented in the module docstring of
`agentshield/policy.py` and demonstrated in
`policies/examples/demo-policy.yaml`. It supports `key: value` pairs,
nested mappings by indentation, `- item` and `- key: value` lists,
and `#` comments. It is **not** a full YAML parser: tabs are rejected,
and anything outside the subset raises `PolicyError` instead of being
silently misinterpreted. Use JSON for complex policies, and never
"extend" the subset parser without tests proving malformed input is
still rejected.

Validate any policy you write or change:

```bash
python -m agentshield check --policy policies/examples/<your-policy>.json
```

And check the decision it produces before trusting it:

```bash
python -m agentshield explain --policy policies/examples/<your-policy>.json \
    --tool <tool> --action <action> --resource <resource> --environment <env>
```

### Policy authoring rules

1. **Deny the dangerous thing explicitly.** Default deny is the
   backstop, but a named deny rule (`deny-db-prod`,
   `deny-deploy-prod`) shows up in the audit reason and in `explain`
   output, so a reviewer can see *why* a call was refused.
2. **Scope narrowly, then widen deliberately.** Start with one tool,
   one action, one environment, and one resource glob. An omitted
   field matches everything — treat every omission as a conscious
   choice and say so in the pull request.
3. **Never put a secret in a policy file.** Secrets come from the
   environment as `AGENTSHIELD_SECRET_<NAME>` and are scoped to tools
   via `secret_scopes`. A policy file containing a credential will be
   rejected, and the credential must be treated as compromised.
4. **Keep rule ids stable and descriptive** (`allow-db-staging`,
   `deny-db-prod`). They appear in audit records and denial reasons;
   renaming one breaks anyone grepping logs for it.
5. **Do not rely on the model to follow the policy.** Authorization
   comes only from policy evaluated by the gateway, never from model
   output, prompt wording, or tool output.

## How to add a policy decision-table test

Policy behaviour is specified by a decision table, not by prose alone.
If your change alters what is allowed or denied, add a row (or a new
test) — a policy change without a test is not ready for review.

The table lives in `TestEngineDecisionTable.test_decision_table` in
`tests/test_agentshield.py`. Each row is
`(call dict, expected allowed, reason substring)`:

```python
({"tool": "db", "action": "query", "resource": "prod.users",
  "environment": "prod"}, False, "deny-db-prod"),
```

To add a case:

1. Decide the expected outcome **before** running the code, and write
   down why — which rule should match, or why no rule should match
   (default deny).
2. Add the row to the table, or add a focused test (like
   `test_deny_wins_over_allow`) if the case exercises a rule
   interaction rather than a single rule.
3. If the case involves the gateway rather than the engine alone
   (approval, budget, secret scoping, audit), add it to the
   `TestGateway` / `TestSecretsAndAudit` fixtures instead — they build
   a real `Gateway` over a temporary workspace with
   `GatewayFixture.setUp()`.
4. Run the full suite. A new test that passes only because the
   implementation is wrong is worse than no test; check the reason
   string, not just the boolean. The decision table asserts the reason
   contains the expected rule id or `"default"`.
5. If you add a new example policy, add a load test proving the JSON
   and YAML-subset forms agree (see
   `test_yaml_subset_matches_json`), and a `check` run in the PR
   description.

For adversarial cases — a policy file that should be rejected — assert
`PolicyError` (see `test_bad_effect_rejected`,
`test_duplicate_rule_ids_rejected`, `test_unknown_rule_field_rejected`).
The loader must fail loudly on malformed input, never guess.

## Pull request expectations

- **Small and reviewable.** One change per PR. If a PR touches the
  policy engine, the gateway check order, approvals, secrets, budgets,
  or audit, say so in the first line — those are the security-critical
  paths.
- **Tests included and passing.** `python -m unittest discover -s tests`
  must be green. New behaviour needs a new test; a behaviour change
  needs the decision table updated.
- **Docs updated in the same PR.** A new policy field, CLI flag, or
  gateway behaviour without a matching update to `README.md`,
  `docs/policy-guide.md`, or `docs/examples-guide.md` is incomplete.
- **No security claims you cannot prove.** Do not describe a change as
  "secure", "production-ready", or "protects against X" unless the
  threat model supports it and a test demonstrates it. This reference
  implementation is explicitly **not** production-secure (see
  `SECURITY.md` and `THREAT_MODEL.md`).
- **No secrets, ever.** No real credentials, tokens, or keys in code,
  tests, fixtures, policies, or commit messages. Use the demo secret
  or an obviously fake value such as `test-secret-123`.
- **No new dependencies** without prior discussion (see "Local setup").
- **Describe the decision, not just the diff.** What call is now
  allowed or denied that was not before? What does `explain` say
  about it? Paste the `check` / `explain` / demo output for policy
  changes.
- **Be kind in review.** Reviewers will ask hard questions about
  security-critical code; that is the job, not a judgement. Answer
  with evidence (a test, a trace, a threat-model reference), and
  expect the same in return.

## Good first contributions

- A new example policy in `policies/examples/` with a decision-table
  test and a section in `docs/examples-guide.md` — for example, a
  read-only research agent, or a staging-only deploy agent.
- More decision-table rows for edge cases (glob `?`, an omitted
  field, a rule matching on `user` or `project`).
- Documentation fixes and troubleshooting entries for errors you hit
  while following the README quickstart on a clean machine.
- Tests for malformed policy files that should be rejected.

## Questions

Open a GitHub Discussion or an issue (for non-security questions).
If you are unsure whether something is a security issue, treat it as
one and report it privately per [SECURITY.md](SECURITY.md) — a false
alarm handled privately costs far less than a real issue discussed
in public.
