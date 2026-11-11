"""AgentShield CLI.

Usage:
    python -m agentshield demo [--policy policies/examples/demo-policy.json]
    python -m agentshield explain --policy <file> --tool db --action query \\
        --resource prod.users --environment prod
    python -m agentshield check --policy <file>   # validate a policy file
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from .approval import ApprovalStore
from .audit import AuditLog
from .budget import Budget, BudgetManager
from .gateway import Gateway, ToolCall
from .policy import Policy, PolicyError
from .secrets import SecretBroker
from .tools import FakeTools


def load_policy(path):
    if path.endswith(".json"):
        return Policy.from_json_file(path)
    if path.endswith((".yaml", ".yml")):
        return Policy.from_yaml_subset_file(path)
    raise PolicyError(f"unsupported policy file (use .json or .yaml): {path}")


def build_gateway(policy, workspace, audit_path):
    broker = SecretBroker(scopes=policy.secret_scopes)
    return Gateway(
        policy=policy,
        tools=FakeTools(workspace),
        broker=broker,
        approvals=ApprovalStore(),
        budgets=BudgetManager(Budget(
            max_calls=policy.budgets.get("max_calls"),
            max_seconds=policy.budgets.get("max_seconds"),
            max_cost=policy.budgets.get("max_cost"),
        )),
        audit=AuditLog(audit_path, redact=broker.redact),
    )


def cmd_demo(args):
    from demo import run_demo
    run_demo(args.policy, args.workspace, args.audit)
    return 0


def cmd_explain(args):
    policy = load_policy(args.policy)
    gateway = build_gateway(policy, args.workspace, args.audit)
    call = ToolCall(tool=args.tool, action=args.action,
                    args={"path": args.resource,
                          "table": args.resource.split(".")[-1],
                          "environment": args.environment},
                    environment=args.environment)
    decision = gateway.explain(call)
    print(f"allowed: {decision.allowed}")
    print(f"reason:  {decision.reason}")
    for step in decision.steps:
        print(f"  - {step}")
    return 0 if decision.allowed else 1


def cmd_check(args):
    try:
        policy = load_policy(args.policy)
    except (PolicyError, OSError) as exc:
        print(f"INVALID: {exc}")
        return 1
    print(f"OK: policy '{policy.name}' v{policy.version}, "
          f"{len(policy.rules)} rules, "
          f"sensitive actions: {list(policy.sensitive_actions) or 'none'}")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(prog="agentshield")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("demo", help="run the scripted demo gateway")
    p.add_argument("--policy", default="policies/examples/demo-policy.json")
    p.add_argument("--workspace", default="demo-workspace")
    p.add_argument("--audit", default="audit.jsonl")
    p.set_defaults(func=cmd_demo)

    p = sub.add_parser("explain", help="explain a call without executing it")
    p.add_argument("--policy", required=True)
    p.add_argument("--tool", required=True)
    p.add_argument("--action", required=True)
    p.add_argument("--resource", default="")
    p.add_argument("--environment", default="staging")
    p.add_argument("--workspace", default="demo-workspace")
    p.add_argument("--audit", default="audit.jsonl")
    p.set_defaults(func=cmd_explain)

    p = sub.add_parser("check", help="validate a policy file")
    p.add_argument("--policy", required=True)
    p.set_defaults(func=cmd_check)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
