"""Deploy-approval example.

A deploy action is blocked without human approval, then approved with
its exact arguments and succeeds. Changing the arguments invalidates
the approval: an approval for deploying service ``web`` does not cover
deploying service ``api`` — the gateway recomputes the approval token
from the actual call, so different args mean a different token.

Run from this directory:   python run.py
Run from the repo root:    python examples/deploy-approval/run.py
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
    print(f"  [{status}] {label:<42} {result['reason']}")
    if result.get("result") is not None:
        print(f"           -> {result['result']!r}")
    return result["allowed"]


def _deploy(service, environment):
    # ToolCall.environment drives the policy resource ("staging"/"prod");
    # args["environment"] is what the tool itself reports deploying to.
    return ToolCall("deploy", "run",
                    {"service": service, "environment": environment},
                    actor="deploy-agent", environment=environment)


def main():
    WORKSPACE.mkdir(exist_ok=True)
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
    failures = []

    deploy_web = _deploy("web", "staging")
    deploy_api = _deploy("api", "staging")

    print("=== 1. Deploy is blocked without approval ===")
    if _show("deploy web -> staging (no approval)",
             gateway.call(deploy_web)):
        failures.append("deploy without approval should have been denied")

    print("\n=== 2. Approved with exact arguments, it succeeds ===")
    token = gateway.request_approval(deploy_web)
    print(f"  approval requested: {token[:16]}... "
          f"(deploy.run service=web environment=staging, exact args shown)")
    gateway.approvals.approve(token)
    print("  human approved.")
    if not _show("deploy web -> staging (approved)",
                 gateway.call(deploy_web)):
        failures.append("approved deploy web should have succeeded")

    print("\n=== 3. Changing the arguments invalidates the approval ===")
    token2 = gateway.request_approval(deploy_web)
    gateway.approvals.approve(token2)
    print("  human approved deploy web -> staging (again).")
    if _show("deploy api -> staging (same approval, new args)",
             gateway.call(deploy_api)):
        failures.append("deploy api must NOT be covered by the web approval")
    print("  The web approval does not cover api: different args, "
          "different approval token.")
    token3 = gateway.request_approval(deploy_api)
    gateway.approvals.approve(token3)
    print("  human approved deploy api -> staging.")
    if not _show("deploy api -> staging (approved for api)",
                 gateway.call(deploy_api)):
        failures.append("approved deploy api should have succeeded")

    print("\n=== 4. Policy still wins: prod is denied even with approval ===")
    deploy_prod = _deploy("web", "prod")
    token4 = gateway.request_approval(deploy_prod)
    gateway.approvals.approve(token4)
    if _show("deploy web -> prod (approved, but prod denied)",
             gateway.call(deploy_prod)):
        failures.append("deploy to prod should have been denied by policy")

    print("\n=== 5. Audit log ===")
    entries = gateway.audit.read()
    print(f"  {len(entries)} entries in audit.jsonl; "
          f"integrity check: {gateway.audit.verify()}")

    if failures:
        print(f"\nFAILED: {len(failures)} check(s):")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print("\nPASS: deploy blocked without approval, approved deploy "
          "succeeded, changed args invalidated the approval, prod denied.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
