"""Budget-limited run example.

A per-run tool-call count and a cost ceiling, shown separately so each
limit is visible on its own:

- Phase A (cost ceiling): max_cost $0.03 from policy.json, call count
  raised out of the way. Each ``files.read`` costs $0.01, so the first
  three reads succeed ($0.03 total) and the fourth is blocked — the run
  stops on cost, not on call count.
- Phase B (call-count ceiling): max_calls 3 from policy.json, cost
  raised out of the way. The first three calls succeed and the fourth
  is blocked — the run stops on count, not on cost.

Denied calls are never charged, so the counters stay exactly where the
budget stopped them. Costs come from the gateway's per-tool price table
(files.list $0.00, files.read $0.01).

Run from this directory:   python run.py
Run from the repo root:    python examples/budget-limited-run/run.py
"""

from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
sys.path.insert(0, str(REPO_ROOT))

from agentshield import (  # noqa: E402
    ApprovalStore, AuditLog, Budget, BudgetManager, Gateway, Policy,
    SecretBroker, ToolCall,
)
from agentshield.tools import FakeTools  # noqa: E402

WORKSPACE = HERE / "workspace"
AUDIT_PATH = HERE / "audit.jsonl"


def _show(label, result):
    status = "ALLOWED" if result["allowed"] else "DENIED "
    print(f"  [{status}] {label:<28} {result['reason']}")
    return result["allowed"]


def _build(policy, budgets):
    return Gateway(
        policy=policy,
        tools=FakeTools(WORKSPACE),
        broker=SecretBroker(scopes=policy.secret_scopes),
        approvals=ApprovalStore(),
        budgets=BudgetManager(Budget(
            max_calls=budgets.get("max_calls"),
            max_seconds=budgets.get("max_seconds"),
            max_cost=budgets.get("max_cost"),
        )),
        audit=AuditLog(str(AUDIT_PATH), redact=lambda t: t),
    )


def main():
    WORKSPACE.mkdir(exist_ok=True)
    for name in ("a.txt", "b.txt", "c.txt", "d.txt", "e.txt"):
        (WORKSPACE / name).write_text(f"budget demo file {name}\n")
    if AUDIT_PATH.exists():
        AUDIT_PATH.unlink()

    policy = Policy.from_json_file(HERE / "policy.json")
    agent = "budget-agent"
    failures = []

    print("=== Phase A. Cost ceiling: max_cost $0.03, reads cost $0.01 each ===")
    cost_gateway = _build(policy, {"max_calls": 100,
                                   "max_cost": policy.budgets["max_cost"]})
    cost_results = []
    for i in range(5):
        cost_results.append(_show(
            f"read {i + 1}: files.read a.txt",
            cost_gateway.call(ToolCall("files", "read", {"path": "a.txt"},
                                       actor=agent))))
    print(f"  budget state: {cost_gateway.budgets.remaining()}")
    if cost_results != [True, True, True, False, False]:
        failures.append(
            f"cost phase: expected 3 allowed then blocked, got {cost_results}")
    if cost_gateway.budgets.remaining()["cost_used"] != 0.03:
        failures.append("cost phase: denied reads must not be charged")

    print("\n=== Phase B. Call-count ceiling: max_calls 3, cost out of the way ===")
    count_gateway = _build(policy, {"max_calls": policy.budgets["max_calls"],
                                    "max_cost": 10.0})
    count_results = []
    for i in range(5):
        count_results.append(_show(
            f"call {i + 1}: files.list workspace",
            count_gateway.call(ToolCall("files", "list", {"path": "."},
                                        actor=agent))))
    print(f"  budget state: {count_gateway.budgets.remaining()}")
    if count_results != [True, True, True, False, False]:
        failures.append(
            f"call-count phase: expected 3 allowed then blocked, got {count_results}")

    print("\n=== Audit log ===")
    entries = count_gateway.audit.read()
    print(f"  {len(entries)} entries in audit.jsonl; "
          f"integrity check: {count_gateway.audit.verify()}")

    if failures:
        print(f"\nFAILED: {len(failures)} check(s):")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print("\nPASS: run stopped at the $0.03 cost ceiling (phase A) and at "
          "the 3-call ceiling (phase B); denied calls were not charged.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
