"""The gateway: route an agent's tool call through budget, policy,
approval, and secret scoping — in that order — before the tool ever runs.

Order of checks (each denial is audited):
0. Budget — charged FIRST, so every attempted call consumes budget,
   including environment-mismatched and malformed ones. (Previously the
   environment check ran first, so an agent could loop mismatched calls
   for free.) A malformed call is charged, then denied.
1. Environment agreement — the environment the tool will actually
   consume (taken from the call's arguments) must match the environment
   declared on the call. A mismatch is denied before policy is evaluated.
2. Policy — default deny; unknown tools/actions are denied, never allowed.
   A policy that fails to evaluate (malformed rule, bad type) denies
   the call instead of crashing the gateway.
3. Approval — sensitive actions need an approval bound to the exact args.
4. Secret scoping — a credential is fetched for this call only, and only
   when the tool is in the secret's scope.
5. Execute the tool; record the outcome in the audit log (redacted).

``call()`` and ``explain()`` never raise for malformed or
attacker-controlled input: fields are sanitised at the gate, and a
last-resort safety net turns any unexpected internal error into a
denial. Argument values that are not JSON values cannot be approved
(``approval_token`` raises TypeError); the gateway denies those calls.

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


def _coerce_text(value):
    """Coerce an attacker-controlled call field to a string.

    A non-string tool/action/actor/environment becomes its ``str()``
    form (an unknown tool then denies by default); ``None`` becomes
    ``""``. This never raises, so the gates below can assume strings.
    """
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return str(value)


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
        environment is used. Non-string values never leak through: they
        fall back to the declared environment (also coerced to a string).
        """
        args = self.args if isinstance(self.args, dict) else {}
        if self.tool in ENV_FROM_ARGS:
            env = args.get("environment")
            if isinstance(env, str) and env:
                return env
        declared = self.environment
        return declared if isinstance(declared, str) else ""

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

        Non-string argument values are coerced to "" for the resource,
        so they match no allow rule and the call denies by default —
        this method never raises on malformed input.
        """
        args = self.args if isinstance(self.args, dict) else {}
        if self.tool == "files":
            path = args.get("path", "")
            if not isinstance(path, str):
                resource = ""
            else:
                resource = path if path.startswith("/") else f"workspace/{path}"
                resource = _normalize_resource(resource)
        elif self.tool == "db":
            table = args.get("table", "")
            env = self.effective_environment()
            resource = f"{env}.{table}" if isinstance(table, str) else ""
        elif self.tool == "deploy":
            resource = self.effective_environment()
        else:
            value = (args.get("path") or args.get("table")
                     or args.get("environment") or "")
            resource = value if isinstance(value, str) else ""
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

    def _sanitize_call(self, call):
        """Return (sanitized ToolCall, malformed_reason).

        Coerces every attacker-controlled field to a safe form: tool,
        action, actor, and environment become strings; args must be a
        mapping (anything else is flagged malformed and replaced with
        ``{}``). Never raises — a call object missing attributes
        entirely still yields a deniable call.
        """
        tool = _coerce_text(getattr(call, "tool", None))
        action = _coerce_text(getattr(call, "action", None))
        actor = _coerce_text(getattr(call, "actor", None))
        environment = _coerce_text(getattr(call, "environment", None))
        args = getattr(call, "args", None)
        malformed = None
        if not isinstance(args, dict):
            malformed = "malformed call: args must be a mapping"
            args = {}
        safe = ToolCall(tool=tool, action=action, args=args, actor=actor,
                        environment=environment)
        return safe, malformed

    def _audit_deny(self, safe, resource, reason, outcome="blocked"):
        self.audit.record(safe.actor, safe.tool, safe.action, resource,
                          "deny", outcome, reason)

    def explain(self, call):
        """Full-gate explain mode: budget + policy + approval, no execution.

        Answers "would this exact call be allowed?" the same way
        :meth:`call` would — including sensitive-action approval and
        budget state — without executing anything, consuming budget, or
        consuming an approval. Never raises for malformed input.
        """
        try:
            return self._explain_inner(call)
        except Exception as exc:  # last-resort safety net: deny, never raise
            return Decision(False, f"Denied: internal error: {exc}",
                            steps=[f"internal error: {exc}"])

    def _explain_inner(self, call):
        safe, malformed = self._sanitize_call(call)
        pcall = self._policy_call(safe)
        steps = []
        cost = TOOL_COSTS.get((safe.tool, safe.action), 0.0)

        if malformed is not None:
            steps.append(f"malformed call: {malformed}")
            return Decision(False, f"Denied: {malformed}", steps=steps)

        # Gate 0: budget (probe only — never records, never latches).
        ok, reason = self.budgets.would_allow(cost)
        if not ok:
            steps.append(f"budget: would block ({reason})")
            return Decision(False, f"Denied: budget would block this call: {reason}",
                            steps=steps)
        steps.append("budget: within limits")

        # Gate 1: environment agreement.
        if safe.tool in ENV_FROM_ARGS and safe.effective_environment() != safe.environment:
            steps.append(
                f"environment mismatch: declared {safe.environment!r} but "
                f"arguments would execute against {safe.effective_environment()!r}")
            return Decision(False,
                            "Denied: environment mismatch between call and arguments",
                            steps=steps)
        steps.append("environment: declared and argument environments agree")

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
        if self.policy.is_sensitive(safe.action):
            try:
                approved = self.approvals.has_approval(
                    safe.tool, safe.action, safe.args)
            except Exception:
                # Non-JSON arguments cannot be approved: deny.
                approved = False
            if approved:
                steps.append("approval: granted for these exact arguments")
            else:
                steps.append("approval: required, none granted for these exact arguments")
                return Decision(
                    False,
                    f"Denied: approval required for sensitive action "
                    f"{safe.tool}.{safe.action}",
                    matched_rules=decision.matched_rules, steps=steps)

        steps.append("all gates pass")
        return Decision(True, decision.reason,
                        matched_rules=decision.matched_rules, steps=steps)

    def request_approval(self, call):
        """Open an approval request showing the exact action and arguments.

        The agent requests; a human grants out of band (see
        :mod:`agentshield.approval`). There is deliberately no gateway
        method to approve — the agent cannot approve its own calls.
        Raises TypeError when the arguments contain non-JSON values
        (no token can be computed for them).
        """
        safe, malformed = self._sanitize_call(call)
        if malformed is not None:
            raise TypeError(malformed)
        return self.approvals.request(safe.tool, safe.action, safe.args,
                                      actor=safe.actor)

    def call(self, call):
        """Route one call. Returns a result dict; never raises."""
        try:
            return self._call_inner(call)
        except Exception as exc:  # last-resort safety net: deny, never raise
            try:
                self.audit.record("gateway", "gateway", "call", "", "deny",
                                  "blocked", f"internal error: {exc}")
            except Exception:
                pass
            return {"allowed": False,
                    "reason": f"Denied: internal error: {exc}",
                    "result": None}

    def _call_inner(self, call):
        safe, malformed = self._sanitize_call(call)
        cost = TOOL_COSTS.get((safe.tool, safe.action), 0.0)

        # 0. Budget — charged FIRST, so every attempted call consumes
        # budget, including environment-mismatched and malformed ones.
        ok, reason = self.budgets.check(cost)
        if not ok:
            self._audit_deny(safe, "", reason)
            return {"allowed": False, "reason": reason, "result": None}
        # Charge the attempt now: denied and erroring calls consume
        # budget too, so they cannot loop for free.
        self.budgets.record(cost)

        if malformed is not None:
            self._audit_deny(safe, "", malformed)
            return {"allowed": False, "reason": malformed, "result": None}

        # 1. Environment agreement: the tool must execute against the
        # environment the call declares. Anything else is denied outright
        # — policy must never be evaluated on one environment while the
        # tool runs against another.
        if safe.tool in ENV_FROM_ARGS and safe.effective_environment() != safe.environment:
            resource = self._policy_call(safe)["resource"]
            reason = (f"environment mismatch: call declares "
                      f"{safe.environment!r} but arguments would execute "
                      f"against {safe.effective_environment()!r}")
            self._audit_deny(safe, resource, reason)
            return {"allowed": False, "reason": reason, "result": None}

        pcall = self._policy_call(safe)
        resource = pcall["resource"]

        # 2. Policy (default deny; evaluation errors deny, never crash).
        try:
            decision = self.engine.evaluate(pcall)
        except Exception as exc:
            reason = f"policy evaluation error: {exc}"
            self._audit_deny(safe, resource, reason)
            return {"allowed": False, "reason": reason, "result": None}
        if not decision.allowed:
            self._audit_deny(safe, resource, decision.reason)
            return {"allowed": False, "reason": decision.reason, "result": None}

        # 3. Human approval for sensitive actions.
        if self.policy.is_sensitive(safe.action):
            try:
                approved = self.approvals.is_approved(
                    safe.tool, safe.action, safe.args)
            except Exception:
                # Non-JSON arguments cannot be approved: deny.
                self._audit_deny(safe, resource,
                                 "approval cannot be verified for non-JSON arguments")
                return {"allowed": False,
                        "reason": "Denied: approval cannot be verified for "
                                  "non-JSON arguments",
                        "result": None}
            if not approved:
                try:
                    token = approval_token(safe.tool, safe.action, safe.args)
                except Exception:
                    self._audit_deny(safe, resource,
                                     "approval cannot be requested for non-JSON arguments")
                    return {"allowed": False,
                            "reason": "Denied: approval cannot be requested for "
                                      "non-JSON arguments",
                            "result": None}
                reason = ("approval required for sensitive action "
                          f"{safe.tool}.{safe.action} (request {token[:16]})")
                self._audit_deny(safe, resource, reason, outcome="awaiting-approval")
                return {"allowed": False, "reason": reason, "result": None,
                        "approval_token": token}

        # 4. Scoped secret, fetched for this call only.
        secret = None
        if safe.tool == "db":
            secret = self.broker.get("DB_PASSWORD", safe.tool)

        # 5. Execute and audit (redacted).
        try:
            result = self.tools.dispatch(safe.tool, safe.action, safe.args,
                                         secret=secret)
        except ToolError as exc:
            self.audit.record(safe.actor, safe.tool, safe.action, resource,
                              "allow", "error", str(exc))
            return {"allowed": True, "reason": "allowed by policy; tool errored",
                    "result": None, "error": str(exc)}
        self.audit.record(safe.actor, safe.tool, safe.action, resource,
                          "allow", "ok", f"cost={cost}")
        return {"allowed": True, "reason": "allowed by policy", "result": result}
