"""The gateway: route an agent's tool call through policy, approval,
budget, and secret scoping — in that order — before the tool ever runs.

Order of checks (each denial is audited):
1. Budget — exceeded budgets block everything.
2. Policy — default deny; unknown tools/actions are denied, never allowed.
3. Approval — sensitive actions need an approval bound to the exact args.
4. Secret scoping — a credential is fetched for this call only, and only
   when the tool is in the secret's scope.
5. Execute the tool; record the outcome in the audit log (redacted).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .approval import approval_token
from .budget import Budget
from .engine import PolicyEngine
from .tools import TOOL_COSTS, ToolError


@dataclass
class ToolCall:
    tool: str
    action: str
    args: dict = field(default_factory=dict)
    actor: str = "agent"
    environment: str = "staging"
    user: str = "dev"
    project: str = "demo"

    def to_policy_call(self):
        """Build the policy view of this call.

        Resources are namespaced per tool so rules stay readable:
        files -> "workspace/<path>", db -> "<env>.<table>",
        deploy -> "<env>". Absolute file paths are left absolute, so they
        never match the workspace glob (and are denied).
        """
        if self.tool == "files":
            path = self.args.get("path", "")
            resource = path if path.startswith("/") else f"workspace/{path}"
        elif self.tool == "db":
            resource = f"{self.environment}.{self.args.get('table', '')}"
        elif self.tool == "deploy":
            resource = self.environment
        else:
            resource = (self.args.get("path") or self.args.get("table")
                        or self.args.get("environment") or "")
        return {
            "tool": self.tool,
            "action": self.action,
            "resource": resource,
            "environment": self.environment,
            "user": self.user,
            "project": self.project,
        }


class Gateway:
    def __init__(self, policy, tools, broker, approvals, budgets, audit):
        self.policy = policy
        self.engine = PolicyEngine(policy)
        self.tools = tools
        self.broker = broker
        self.approvals = approvals
        self.budgets = budgets
        self.audit = audit

    def explain(self, call):
        """Policy explain mode: why would this call be allowed/denied?"""
        return self.engine.explain(call.to_policy_call())

    def request_approval(self, call):
        """Open an approval request showing the exact action and arguments."""
        return self.approvals.request(call.tool, call.action, call.args,
                                      actor=call.actor)

    def call(self, call):
        """Route one call. Returns a result dict; never raises for denials."""
        resource = call.to_policy_call()["resource"]
        cost = TOOL_COSTS.get((call.tool, call.action), 0.0)

        # 1. Budget.
        ok, reason = self.budgets.check(cost)
        if not ok:
            self.audit.record(call.actor, call.tool, call.action, resource,
                              "deny", "blocked", reason)
            return {"allowed": False, "reason": reason, "result": None}

        # 2. Policy (default deny).
        decision = self.engine.evaluate(call.to_policy_call())
        if not decision.allowed:
            self.audit.record(call.actor, call.tool, call.action, resource,
                              "deny", "blocked", decision.reason)
            return {"allowed": False, "reason": decision.reason, "result": None}

        # 3. Human approval for sensitive actions.
        if self.policy.is_sensitive(call.action):
            if not self.approvals.is_approved(call.tool, call.action, call.args):
                token = approval_token(call.tool, call.action, call.args)
                reason = ("approval required for sensitive action "
                          f"{call.tool}.{call.action} (request {token[:16]})")
                self.audit.record(call.actor, call.tool, call.action, resource,
                                  "deny", "awaiting-approval", reason)
                return {"allowed": False, "reason": reason, "result": None,
                        "approval_token": token}

        # 4. Scoped secret, fetched for this call only.
        secret = None
        if call.tool == "db":
            secret = self.broker.get("DB_PASSWORD", call.tool)

        # 5. Execute and audit (redacted).
        try:
            result = self.tools.dispatch(call.tool, call.action, call.args,
                                         secret=secret)
        except ToolError as exc:
            self.audit.record(call.actor, call.tool, call.action, resource,
                              "allow", "error", str(exc))
            return {"allowed": True, "reason": "allowed by policy; tool errored",
                    "result": None, "error": str(exc)}
        self.budgets.record(cost)
        self.audit.record(call.actor, call.tool, call.action, resource,
                          "allow", "ok", f"cost={cost}")
        return {"allowed": True, "reason": "allowed by policy", "result": result}
