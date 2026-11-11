"""Read-only agent example.

An agent that may only read/list approved paths. Reads inside the
workspace succeed; a write/delete attempt — and a read outside the
approved directory — are denied by policy (default deny: there is
simply no allow rule for ``files.delete``).

Run from this directory:   python run.py
Run from the repo root:    python examples/read-only-agent/run.py
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
    print(f"  [{status}] {label:<32} {result['reason']}")
    if result.get("result") is not None:
        print(f"           -> {result['result']!r}")
    return result["allowed"]


def main():
    # Idempotent workspace: re-created on every run so the demo is
    # repeatable (the delete attempt below must not remove anything).
    WORKSPACE.mkdir(exist_ok=True)
    (WORKSPACE / "notes.txt").write_text(
        "read-only demo: ship the gateway, not the prompt.\n")
    (WORKSPACE / "data.txt").write_text("read-only demo data: 42\n")
    if AUDIT_PATH.exists():
        AUDIT_PATH.unlink()

    policy = Policy.from_json_file(HERE / "policy.json")
    gateway = Gateway(
        policy=policy,
        tools=FakeTools(WORKSPACE),
        broker=SecretBroker(scopes=policy.secret_scopes),
        approvals=ApprovalStore(),
        budgets=BudgetManager(Budget(
            max_calls=policy.budgets.get("max_calls"),
            max_seconds=policy.budgets.get("max_seconds"),
            max_cost=policy.budgets.get("max_cost"),
        )),
        audit=AuditLog(str(AUDIT_PATH), redact=lambda t: t),
    )
    agent = "read-only-agent"
    failures = []

    print("=== 1. Reads inside the approved directory succeed ===")
    if not _show("files.list workspace",
                 gateway.call(ToolCall("files", "list", {"path": "."}, actor=agent))):
        failures.append("files.list should have been allowed")
    if not _show("files.read notes.txt",
                 gateway.call(ToolCall("files", "read", {"path": "notes.txt"}, actor=agent))):
        failures.append("files.read notes.txt should have been allowed")

    print("\n=== 2. Reads outside the approved directory are denied ===")
    if _show("files.read /etc/passwd",
             gateway.call(ToolCall("files", "read", {"path": "/etc/passwd"}, actor=agent))):
        failures.append("files.read /etc/passwd should have been denied")

    print("\n=== 3. A write/delete attempt is denied ===")
    if _show("files.delete notes.txt",
             gateway.call(ToolCall("files", "delete", {"path": "notes.txt"}, actor=agent))):
        failures.append("files.delete should have been denied")
    still_there = (WORKSPACE / "notes.txt").exists()
    print(f"  notes.txt still on disk after denied delete: {still_there}")
    if not still_there:
        failures.append("notes.txt must survive a denied delete")

    print("\n=== 4. Explain mode: why, without executing ===")
    decision = gateway.explain(
        ToolCall("files", "delete", {"path": "notes.txt"}, actor=agent))
    print(f"  files.delete notes.txt: "
          f"{'ALLOWED' if decision.allowed else 'DENIED'} — {decision.reason}")
    if decision.allowed:
        failures.append("explain(files.delete) should be DENIED")

    print("\n=== 5. Audit log ===")
    entries = gateway.audit.read()
    print(f"  {len(entries)} entries in audit.jsonl; "
          f"integrity check: {gateway.audit.verify()}")

    if failures:
        print(f"\nFAILED: {len(failures)} check(s):")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print("\nPASS: reads allowed, forbidden read and delete denied, "
          "file untouched.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
