# Examples Guide

What the demo and the runnable examples in `examples/` show, how to
run them, and how to use them as starting points for your own policies.

All examples are self-contained: they build a real `Gateway` over the
local fake tools (`agentshield/tools.py` — a workspace-scoped file
tool, a staging/production fake database, and deploy), run a scripted
sequence of calls, and print `PASS` or `FAILED` at the end. Each one
recreates its workspace on every run. The per-example `audit.jsonl`
files are rewritten by the examples themselves; the main demo's audit
log is append-only and is never truncated. Run them from the
repository root, or from inside the example directory — both work.

> **Note:** `docs/threat-model-notes.md` was deliberately not written.
> The threat model lives in one place, [THREAT_MODEL.md](../THREAT_MODEL.md),
> and duplicating it here would let the two copies drift apart. If you
> need the security story, read that file; this guide is about running
> the examples.

## The main demo: `demo.py`

```bash
python demo.py                    # scripted demo
python -m agentshield demo        # same demo via the CLI
```

The demo uses `policies/examples/demo-policy.json` (7 rules,
`sensitive_actions` `delete`/`run`/`send`/`buy`, budgets 50 calls /
300 seconds / $5.00, `DB_PASSWORD` scoped to `db` only) and a
workspace at `demo-workspace/` with `notes.txt` and `data.txt`. It
walks through eight sections:

1. **Reads inside the approved directory work** — `files.list` and
   `files.read notes.txt` are allowed by `allow-files-in-workspace`
   / `allow-read-workspace`.
2. **Forbidden paths and environments are blocked** — `files.read
   /etc/passwd` is denied by default (an absolute path never matches
   `workspace/*`); `db.query staging.users` is allowed by
   `allow-db-staging`; `db.query prod.users` is denied by
   `deny-db-prod`.
3. **Sensitive actions need human approval** — `files.delete
   notes.txt` is refused without approval, then succeeds after a
   human approves the exact call.
4. **Changing the arguments invalidates the approval** — an approval
   for deleting `data.txt` does not cover deleting `other.txt`;
   the original approved call still succeeds.
5. **Unknown tools are denied by default** — `shell.exec 'rm -rf /'`
   is denied; there is no rule for `shell` at all.
6. **Explain mode** — the demo asks why `db.query prod.users` and
   `files.delete data.txt` would be decided the way they are, without
   executing either.
7. **Budgets** — a second gateway with `max_calls: 2` allows two
   `files.list` calls and blocks the third.
8. **Audit log** — the demo prints the entry count in `audit.jsonl`,
   verifies the demo secret does not appear in the file, shows a
   redaction check, and runs `audit.verify()` (which must report
   0 problems).

The demo sets a demo-only secret in-process
(`s3cr3t-db-password-123`). Never point it at a real workspace or a
real secret. Expected end state: the audit file contains no secret
value, `verify()` reports `{'entries': N, 'problems': [], 'ok': True}`,
and `notes.txt`/`data.txt` are recreated on the next run.

## Example 1: read-only agent — `examples/read-only-agent/`

```bash
python examples/read-only-agent/run.py
```

**The idea:** an agent that may only read and list inside the
workspace. Its policy (`policy.json`, 2 rules) allows `files.list`
and `files.read` on `workspace/*` and nothing else; `delete` is
listed in `sensitive_actions`, and `secret_scopes` is empty.

**What it proves, step by step:**

1. `files.list` and `files.read notes.txt` succeed.
2. `files.read /etc/passwd` is denied — the absolute path never
   matches the workspace glob.
3. `files.delete notes.txt` is denied by default deny (there is no
   allow rule for `delete`), and the script checks `notes.txt` is
   still on disk afterwards: a denied call must have no effect.
4. Explain mode agrees: `files.delete notes.txt` is `DENIED`, without
   executing anything.
5. The audit log holds 4 entries and `verify()` reports ok.

**Use it as a template when:** you want an agent that can research,
summarise, or answer questions about files, but must not change
anything. Copy the directory, keep the two allow rules, and add a
deny rule for anything you want to be explicit about.

## Example 2: deploy approval — `examples/deploy-approval/`

```bash
python examples/deploy-approval/run.py
```

**The idea:** deploys are the sensitive action. Its policy
(`policy.json`, 2 rules) allows `deploy.run` to `staging` and
explicitly denies `deploy.run` to `prod`; `run` is the only
sensitive action.

**What it proves, step by step:**

1. Deploying service `web` to staging without approval is blocked.
2. After a human approves that exact call, it succeeds.
3. The same approval does **not** cover deploying service `api`:
   different arguments produce a different approval token, so the
   `api` deploy is blocked until it gets its own approval — and then
   it succeeds.
4. Policy still wins over approval: deploying `web` to prod is
   denied by `deny-deploy-prod` even though a human approved it.
   Approvals never override a policy denial.
5. The audit log holds 5 entries and `verify()` reports ok.

**Use it as a template when:** an agent may act in staging but
needs a human in the loop for every deploy, and prod must stay
off-limits regardless of who approves what. The pattern generalises
to any irreversible action: allow the safe environment, deny the
dangerous one, and put the action in `sensitive_actions`.

## Example 3: budget-limited run — `examples/budget-limited-run/`

```bash
python examples/budget-limited-run/run.py
```

**The idea:** show the two budget ceilings separately, so each limit
is visible on its own. Its policy (`policy.json`) sets
`max_calls: 3`, `max_cost: $0.03`, `max_seconds: 300`, and allows only
`files.list` and `files.read` on `workspace/*`. Costs come from the
gateway's price table: `files.list` $0.00, `files.read` $0.01. The
workspace holds five files, `a.txt`–`e.txt`.

**What it proves, step by step:**

- **Phase A — cost ceiling:** with the call count raised to 100 so it
  cannot interfere, five `files.read` calls are attempted. The first
  three succeed ($0.03 total) and the fourth and fifth are blocked.
  The run stops on cost, not on call count, and the budget state
  shows `cost_used: 0.03` — the reads blocked by the budget itself
  were not charged (every attempt that passes the budget check is
  charged, even if policy or the tool then refuses it).
- **Phase B — call-count ceiling:** with the cost ceiling raised to
  $10.00, five `files.list` calls are attempted. The first three
  succeed and the fourth and fifth are blocked. The run stops on
  count, not on cost.
- The audit log holds 10 entries (one per attempted call, allowed or
  denied) and `verify()` reports ok.

**Use it as a template when:** you need a runaway-loop guard — an
agent that retries, loops, or calls tools in a tight cycle. Pick the
ceiling from the blast radius you can tolerate, and remember the
block latches: once a budget is exceeded, later calls stay blocked
for the rest of the run.

## Reading an audit log

Every example writes its own `audit.jsonl` (one JSON object per
line). An entry looks like this (fields may vary by run):

```json
{"ts": "2026-11-11T10:00:00+00:00", "run_id": "run_9f2c1a7b4e5d6a01", "actor": "demo-agent",
 "tool": "db", "action": "query", "resource": "prod.users",
 "decision": "deny", "outcome": "denied by rule 'deny-db-prod'", "detail": "",
 "prev_hash": "0000…", "hash": "a1b2…"}
```

- `run_id` is unique per gateway run (`run_<16 hex>`), never a constant.
- `decision` is `allow` or `deny`; `outcome` is the human-readable
  reason, naming the rule when one matched.
- Denials are recorded too — a log with only successes cannot show
  what was stopped.
- Secrets are redacted before writing: a secret value appears as
  `[REDACTED:<NAME>]`, never in plaintext.
- Check integrity with `AuditLog.verify()` (or by reading the
  `verify()` line each example prints): it confirms every line parses
  as JSON, carries the required fields (`ts`, `run_id`, `actor`,
  `tool`, `action`, `resource`, `decision`, `outcome`, `prev_hash`,
  `hash`), and that the hash chain is intact — flipping, reordering,
  or deleting a retained entry is detected. Deleting the tail of the
  log or the whole file is not detectable from the file alone, as
  [THREAT_MODEL.md](../THREAT_MODEL.md) states.

## Writing your own example

1. Copy the closest example directory (`read-only-agent` is the
   simplest starting point).
2. Write `policy.json` for your scenario — see
   [docs/policy-guide.md](policy-guide.md) for the format, and keep
   the policy minimal: allow only what the example needs.
3. Write `run.py` following the existing pattern: build a `Gateway`
   from `Policy`, `SecretBroker`, `ApprovalStore`, `BudgetManager`,
   and `AuditLog` (see `demo.py`'s `build()` for the canonical
   wiring), recreate the workspace on each run, collect failures in
   a list, print `PASS`/`FAILED`, and exit non-zero on failure.
   An example that cannot fail is not a test — assert the denial
   cases as well as the allowed ones, and assert side effects (a
   file still on disk after a denied delete).
4. Validate the policy (`python -m agentshield check --policy
   <your>/policy.json`) and run it from both the repo root and the
   example directory.
5. Add a section to this guide describing what the example proves,
   and — if it exercises a new policy behaviour — a decision-table
   test in `tests/test_agentshield.py` (see
   [CONTRIBUTING.md](../CONTRIBUTING.md)).

Do not add an example that needs network access, a real credential,
or a third-party dependency. Examples must run on a clean checkout
with `python3` alone.
