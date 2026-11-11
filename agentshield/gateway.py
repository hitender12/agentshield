"""The gateway: route an agent's tool call through policy, approval,
budget, and secret scoping — in that order — before the tool ever runs.

Order of checks (each denial is audited):
0. Environment agreement — the environment the tool will actually
   consume (taken from the call's arguments) must match the environment
   declared on the call. A mismatch is denied before anything else.
1. Budget — exceeded budgets block everything. Every *attempted* call
   is charged once the budget check passes, whether policy, approval,
   or the tool itself then refuses it.
2. Policy — default deny; unknown tools/actions are denied, never allowed.
   A policy that fails to evaluate (malformed rule, bad type) denies
   the call instead of crashing the gateway.
3. Approval — sensitive actions need an approval bound to the exact args.
4. Secret scoping — a credential is fetched for this call only, and only
   when the tool is in the secret's scope.
5. Execute the tool; record the outcome in the audit log (redacted).

Identity: ``user``/``project`` are bound to the gateway *session* at
construction. The per-call fields on ToolCall are caller-controlled and
are ignored for policy evaluation — an agent cannot claim to be another
user to escape a deny rule.
"""

from __future__ import annotations

import posixpath
from dataclasses import dataclass, field

from .approval import approval_token
from .engine import Decision, PolicyEngine
from .tools import TOOL_COSTS, ToolError

# Tools whose arguments carry the environment they will execute against.
# For these, the policy resource and environment must be derived from the
# arguments, never from a separately declared field.
ENV_FROM_ARGS = ("db", "deploy")


def _normalize_resource(resource):
    """Collapse ``.``/``..`` segments of a workspace resource.

    ``fnmatch`` ``*`` crosses ``/``, so a raw ``workspace/../secret.txt``
    would match a ``workspace/*`` allow rule. Normalising first makes a
    traversal resolve to the path it actually names (``secret.txt``),
    which no workspace rule matches, so it is denied by default. The
    workspace root itself keeps its canonical ``workspace/.`` form so
    ``files.list`` on ``.`` still matches ``workspace/*``.
    """
    if not (resource.startswith("workspace/") or resource == "workspace"):
        return resource
    normalized = posixpath.normpath(resource)
    if normalized == "workspace":
        return "workspace/."
    return normalized


@dataclass
class ToolCall:
    tool: str
    action: str
    args: dict = field(default_factory=dict)
    actor: str = "agent"
    environment: str = "staging"
    user: str = "dev"
    project: str = "demo"

    def effective_environment(self):
        """The environment the tool will actually consume.

        For tools whose arguments carry an environment, that argument is
        authoritative — it is what the tool reads. Otherwise the declared
        environment is used.
        """
        if self.tool in ENV_FROM_ARGS:
            env = self.args.get("environment")
            if isinstance(env, str) and env:
                return env
        return self.environment

    def to_policy_call(self, session_user=None, session_project=None):
        """Build the policy view of this call.

        Resources are namespaced per tool so rules stay readable:
        files -> "workspace/<path>", db -> "<env>.<table>",
        deploy -> "<env>". Absolute file paths are left absolute, so they
        never match the workspace glob (and are denied).

        The environment and resource always come from the arguments the
        tool will consume, never from the declared field alone. Identity
        comes from the gateway session when supplied; the per-call
        user/project fields are caller-controlled and ignored then.
        """
        if self.tool == "files":
            path = self.args.get("path", "")
            resource = path if path.startswith("/") else f"workspace/{path}"
            resource = _normalize_resource(resource)
        elif self.tool == "db":
            resource = f"{self.effective_environment()}.{self.args.get('table', '')}"
        elif self.tool == "deploy":
            resource = self.effective_environment()
        else:
            resource = (self.args.get("path") or self.args.get("table")
                        or self.args.get("environment") or "")
        return {
            "tool": self.tool,
            "action": self.action,
            "resource": resource,
            "environment": self.effective_environment(),
            "user": session_user if session_user is not None else self.user,
            "project": session_project if session_project is not None else self.project,
        }


class Gateway:
    def __init__(self, policy, tools, broker, approvals, budgets, audit,
                 user="dev", project="demo"):
        """user/project: the identity this gateway session acts as.

        Policy rules on user/project are evaluated against these values,
        not against anything the agent puts on a call.
        """
        self.policy = policy
        self.engine = PolicyEngine(policy)
        self.tools = tools
        self.broker = broker
        self.approvals = approvals
        self.budgets = budgets
        self.audit = audit
        self.user = user
        self.project = project

    def _policy_call(self, call):
        return call.to_policy_call(session_user=self.user,
                                   session_project=self.project)

    def explain(self, call):
        """Full-gate explain mode: budget + policy + approval, no execution.

        Answers "would this exact call be allowed?" the same way
        :meth:`call` would — including sensitive-action approval and
        budget state — without executing anything, consuming budget, or
        consuming an approval.
        """
        pcall = self._policy_call(call)
        steps = []
        cost = TOOL_COSTS.get((call.tool, call.action), 0.0)

        # Gate 0: environment agreement.
        if call.tool in ENV_FROM_ARGS and call.effective_environment() != call.environment:
            steps.append(
                f"environment mismatch: declared {call.environment!r} but "
                f"arguments would execute against {call.effective_environment()!r}")
            return Decision(False,
                            "Denied: environment mismatch between call and arguments",
                            steps=steps)
        steps.append("environment: declared and argument environments agree")

        # Gate 1: budget (probe only — never records, never latches).
        ok, reason = self.budgets.would_allow(cost)
        if not ok:
            steps.append(f"budget: would block ({reason})")
            return Decision(False, f"Denied: budget would block this call: {reason}",
                            steps=steps)
        steps.append("budget: within limits")

        # Gate 2: policy.
        try:
            decision = self.engine.evaluate(pcall)
        except Exception as exc:  # malformed policy must deny, never crash
            steps.append(f"policy evaluation failed: {exc}")
            return Decision(False, "Denied: policy evaluation error", steps=steps)
        steps.extend(decision.steps)
        if not decision.allowed:
            return Decision(False, decision.reason,
                            matched_rules=decision.matched_rules, steps=steps)

        # Gate 3: approval for sensitive actions (peek, never consume).
        if self.policy.is_sensitive(call.action):
            if self.approvals.has_approval(call.tool, call.action, call.args):
                steps.append("approval: granted for these exact arguments")
            else:
                steps.append("approval: required, none granted for these exact arguments")
                return Decision(
                    False,
                    f"Denied: approval required for sensitive action "
                    f"{call.tool}.{call.action}",
                    matched_rules=decision.matched_rules, steps=steps)

        steps.append("all gates pass")
        return Decision(True, decision.reason,
                        matched_rules=decision.matched_rules, steps=steps)

    def request_approval(self, call):
        """Open an approval request showing the exact action and arguments.

        The agent requests; a human grants out of band (see
        :mod:`agentshield.approval`). There is deliberately no gateway
        method to approve — the agent cannot approve its own calls.
        """
        return self.approvals.request(call.tool, call.action, call.args,
                                      actor=call.actor)

    def call(self, call):
        """Route one call. Returns a result dict; never raises for denials."""
        # 0. Environment agreement: the tool must execute against the
        # environment the call declares. Anything else is denied outright
        # — policy must never be evaluated on one environment while the
        # tool runs against another.
        if call.tool in ENV_FROM_ARGS and call.effective_environment() != call.environment:
            resource = self._policy_call(call)["resource"]
            reason = (f"environment mismatch: call declares "
                      f"{call.environment!r} but arguments would execute "
                      f"against {call.effective_environment()!r}")
            self.audit.record(call.actor, call.tool, call.action, resource,
                              "deny", "blocked", reason)
            return {"allowed": False, "reason": reason, "result": None}

        pcall = self._policy_call(call)
        resource = pcall["resource"]
        cost = TOOL_COSTS.get((call.tool, call.action), 0.0)

        # 1. Budget.
        ok, reason = self.budgets.check(cost)
        if not ok:
            self.audit.record(call.actor, call.tool, call.action, resource,
                              "deny", "blocked", reason)
            return {"allowed": False, "reason": reason, "result": None}
        # Charge the attempt now: denied and erroring calls consume
        # budget too, so they cannot loop for free.
        self.budgets.record(cost)

        # 2. Policy (default deny; evaluation errors deny, never crash).
        try:
            decision = self.engine.evaluate(pcall)
        except Exception as exc:
            reason = f"policy evaluation error: {exc}"
            self.audit.record(call.actor, call.tool, call.action, resource,
                              "deny", "blocked", reason)
            return {"allowed": False, "reason": reason, "result": None}
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
        self.audit.record(call.actor, call.tool, call.action, resource,
                          "allow", "ok", f"cost={cost}")
        return {"allowed": True, "reason": "allowed by policy", "result": result}
