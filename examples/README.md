# AgentShield examples

Runnable, self-checking demos of the AgentShield gateway. Each example
lives in its own directory with its own small policy file (`policy.json`)
and runner script (`run.py`). Each runner builds its own workspace and
audit log on every run, prints what was allowed/denied and why, and
exits non-zero if any expected outcome does not happen — so `PASS` at
the end means the gateway behaved as the example claims.

All examples use only the Python standard library plus the `agentshield`
package at the repo root; no API keys, network, or MCP server needed.

## Examples

### 1. `read-only-agent/` — a strict read-only agent

An agent that may only list and read files inside an approved workspace.

- `files.list` and `files.read` inside the workspace: **allowed**.
- `files.read /etc/passwd` (outside the approved directory): **denied**
  by default — no allow rule matches an absolute path.
- `files.delete notes.txt` (a write/delete attempt): **denied** — the
  policy has no allow rule for `delete` at all, and the file is still
  on disk afterwards. Explain mode shows the same denial without
  executing anything.

Run it:

```bash
python examples/read-only-agent/run.py   # from the repo root
# or
cd examples/read-only-agent && python run.py
```

### 2. `deploy-approval/` — a deploy-approval flow

A deploy that needs a human approval bound to the exact action and
arguments (`deploy.run`, staging only; prod is denied by policy).

- `deploy web -> staging` with no approval: **blocked**, awaiting approval.
- Human approves the exact call (`service=web`, `environment=staging`):
  the same call **succeeds** (`deployed web to staging`).
- The approval is then re-issued for `web`, but the agent tries
  `deploy api -> staging` instead: **blocked** — different arguments
  produce a different approval token, so the `web` approval does not
  cover `api`. Approving `api` explicitly lets it succeed.
- Bonus: `deploy web -> prod` is **denied by policy** even with an
  approval — policy still wins over approval.

Run it:

```bash
python examples/deploy-approval/run.py   # from the repo root
# or
cd examples/deploy-approval && python run.py
```

### 3. `budget-limited-run/` — a budget-limited run

A per-run tool-call count and a cost ceiling, shown in two phases so
each limit is visible on its own (limits come from `policy.json`:
`max_calls: 3`, `max_cost: 0.03`).

- **Phase A — cost ceiling:** `max_cost` $0.03 with the call count
  raised out of the way. Each `files.read` costs $0.01, so the first
  three reads succeed ($0.03 total) and the fourth is blocked with
  `cost budget exceeded`.
- **Phase B — call-count ceiling:** `max_calls` 3 with the cost ceiling
  raised out of the way. The first three calls succeed and the fourth
  is blocked with `call budget exceeded: 3/3 calls`.
- Denied calls are never charged, so the counters stay exactly where
  the budget stopped them.

Run it:

```bash
python examples/budget-limited-run/run.py   # from the repo root
# or
cd examples/budget-limited-run && python run.py
```

## Files each example creates at run time

Running an example creates (or recreates) inside its own directory:

- `workspace/` — the fake tool workspace the gateway routes to.
- `audit.jsonl` — the append-only audit log for that run; each runner
  prints its entry count and integrity check.

## See also

- `../demo.py` — the full gateway demo (reads, forbidden paths, staging
  vs prod, approvals, unknown tools, explain mode, budgets, audit
  redaction) in one script.
- `../policies/examples/demo-policy.json` — the policy the full demo uses.
