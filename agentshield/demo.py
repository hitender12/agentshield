"""AgentShield demo: a fake agent routes calls through the gateway.

Shows: allowed reads, a denied forbidden path, staging allowed vs prod
denied, delete blocked without approval, approval then success, approval
invalidated when arguments change, an unknown tool denied by default,
explain mode, budget enforcement, and an audit log with no secrets.

Run:  python demo.py            (or: python -m agentshield demo)

Paths default to the repository root, so the demo works from any
working directory. The audit log is append-only: this demo never
deletes or truncates it — a fresh run appends to whatever is there.

The approval step below is the *human* side of the flow: in a real
deployment the ``approve(...)`` call happens out of band (a CLI prompt,
a web UI, a chat confirmation), never from agent code. The gateway
exposes no approve method, so the agent cannot approve its own calls;
this script stands in for the human operator.
"""

from __future__ import annotations

import os
from pathlib import Path

from agentshield import (  # noqa: E402
    ApprovalStore, AuditLog, Budget, BudgetManager, Gateway, Policy,
    SecretBroker, ToolCall,
)
from agentshield.tools import FakeTools  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent

# Demo-only secret, set in-process so the demo is self-contained. Real use:
# export AGENTSHIELD_SECRET_DB_PASSWORD='...' before starting the gateway.
DEMO_SECRET = "s3cr3t-db-password-123"


def _section(title):
    print(f"\n=== {title} ===")


def _show(label, result):
    status = "ALLOWED" if result["allowed"] else "DENIED "
    print(f"  [{status}] {label:<38} {result['reason']}")
    if result.get("result") is not None:
        print(f"           -> {result['result']!r}")


def build(policy_path, workspace, audit_path, budgets=None):
    policy = Policy.from_json_file(policy_path)
    broker = SecretBroker(scopes=policy.secret_scopes)
    budget_cfg = budgets if budgets is not None else policy.budgets
    gateway = Gateway(
        policy=policy,
        tools=FakeTools(workspace),
        broker=broker,
        approvals=ApprovalStore(),
        budgets=BudgetManager(Budget(
            max_calls=budget_cfg.get("max_calls"),
            max_seconds=budget_cfg.get("max_seconds"),
            max_cost=budget_cfg.get("max_cost"),
        )),
        audit=AuditLog(audit_path, redact=broker.redact),
    )
    return gateway, broker


def run_demo(policy_path=None, workspace=None, audit_path=None):
    policy_path = policy_path or str(REPO_ROOT / "policies" / "examples" / "demo-policy.json")
    workspace = workspace or str(REPO_ROOT / "demo-workspace")
    audit_path = audit_path or str(REPO_ROOT / "audit.jsonl")
    os.environ["AGENTSHIELD_SECRET_DB_PASSWORD"] = DEMO_SECRET
    # Idempotent demo workspace (the demo deletes a file).
    os.makedirs(workspace, exist_ok=True)
    with open(os.path.join(workspace, "notes.txt"), "w") as fh:
        fh.write("demo notes: ship the gateway, not the prompt.\n")
    with open(os.path.join(workspace, "data.txt"), "w") as fh:
        fh.write("demo data: 42\n")
    # NOTE: the audit log is append-only — it is never deleted or
    # truncated here. A repeat run appends new entries to the old ones.

    gateway, broker = build(policy_path, workspace, audit_path)
    agent = "demo-agent"

    _section("1. Reads inside the approved directory work")
    _show("files.list workspace",
          gateway.call(ToolCall("files", "list", {"path": "."}, actor=agent)))
    _show("files.read notes.txt",
          gateway.call(ToolCall("files", "read", {"path": "notes.txt"}, actor=agent)))

    _section("2. Forbidden paths and environments are blocked by policy")
    _show("files.read /etc/passwd",
          gateway.call(ToolCall("files", "read", {"path": "/etc/passwd"}, actor=agent)))
    _show("db.query staging.users",
          gateway.call(ToolCall("db", "query",
                                {"environment": "staging", "table": "users"},
                                actor=agent, environment="staging")))
    _show("db.query prod.users",
          gateway.call(ToolCall("db", "query",
                                {"environment": "prod", "table": "users"},
                                actor=agent, environment="prod")))

    _section("3. Sensitive actions need human approval")
    delete = ToolCall("files", "delete", {"path": "notes.txt"}, actor=agent)
    _show("files.delete notes.txt (no approval)",
          gateway.call(delete))
    token = gateway.request_approval(delete)
    print(f"  approval requested: {token[:16]}... "
          f"(files.delete notes.txt, exact args shown to human)")
    # Human step (out of band in production — this line stands in for
    # the human operator, not the agent).
    gateway.approvals.approve(token, actor="human")
    print("  human approved.")
    _show("files.delete notes.txt (approved)",
          gateway.call(delete))

    _section("4. Changing the arguments invalidates the approval")
    delete_data = ToolCall("files", "delete", {"path": "data.txt"}, actor=agent)
    token2 = gateway.request_approval(delete_data)
    gateway.approvals.approve(token2, actor="human")
    print("  human approved files.delete data.txt.")
    _show("files.delete other.txt (different args)",
          gateway.call(ToolCall("files", "delete", {"path": "other.txt"}, actor=agent)))
    _show("files.delete data.txt (approved args)",
          gateway.call(delete_data))

    _section("5. Unknown tools are denied by default")
    _show("shell.exec 'rm -rf /'",
          gateway.call(ToolCall("shell", "exec", {"command": "rm -rf /"}, actor=agent)))

    _section("6. Explain mode: why, without executing")
    for call in (
        ToolCall("db", "query", {"environment": "prod", "table": "users"},
                 actor=agent, environment="prod"),
        ToolCall("files", "delete", {"path": "data.txt"}, actor=agent),
    ):
        d = gateway.explain(call)
        print(f"  {call.tool}.{call.action} {call.args}: "
              f"{'ALLOWED' if d.allowed else 'DENIED'} — {d.reason}")

    _section("7. Budgets: a 2-call run blocks the third call")
    small, _ = build(policy_path, workspace, audit_path,
                     budgets={"max_calls": 2})
    for i in range(3):
        _show(f"call {i + 1}: files.list",
              small.call(ToolCall("files", "list", {"path": "."}, actor=agent)))

    _section("8. Audit log: everything recorded, secrets redacted")
    entries = gateway.audit.read()
    print(f"  {len(entries)} entries in {audit_path}")
    raw = open(audit_path, encoding="utf-8").read()
    print(f"  secret appears in audit file: {DEMO_SECRET in raw} (must be False)")
    leaked = broker.redact(f"token was {DEMO_SECRET} in this string")
    print(f"  redaction check: {leaked!r}")
    print(f"  audit integrity: {gateway.audit.verify()}")


if __name__ == "__main__":
    run_demo()
