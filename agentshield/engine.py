"""Policy engine: allow/deny evaluation with default deny.

Evaluation order (deny wins):
1. Any matching ``deny`` rule -> DENY, naming the rule.
2. Any matching ``allow`` rule -> ALLOW, naming the rule.
3. No matching rule -> DENY (default deny), saying so explicitly.

``explain()`` returns the same decision plus the evaluation steps, so a
developer can ask "why would this be allowed/denied?" without executing it.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Decision:
    allowed: bool
    reason: str
    matched_rules: list = field(default_factory=list)
    steps: list = field(default_factory=list)

    def __bool__(self):
        return self.allowed


class PolicyEngine:
    """Stateless evaluator over a :class:`~agentshield.policy.Policy`."""

    def __init__(self, policy):
        self.policy = policy

    def evaluate(self, call):
        """Evaluate a call dict; returns a :class:`Decision`."""
        steps = []
        matched_deny = [r for r in self.policy.rules
                        if r.effect == "deny" and r.matches(call)]
        matched_allow = [r for r in self.policy.rules
                         if r.effect == "allow" and r.matches(call)]

        if matched_deny:
            rule = matched_deny[0]
            steps.append(f"deny rule matched: {rule.describe()}")
            return Decision(
                allowed=False,
                reason=f"Denied by rule '{rule.id}'",
                matched_rules=[r.id for r in matched_deny],
                steps=steps,
            )
        if matched_allow:
            rule = matched_allow[0]
            steps.append(f"allow rule matched: {rule.describe()}")
            if len(matched_allow) > 1:
                steps.append(
                    "also matched: " + ", ".join(r.id for r in matched_allow[1:]))
            return Decision(
                allowed=True,
                reason=f"Allowed by rule '{rule.id}'",
                matched_rules=[r.id for r in matched_allow],
                steps=steps,
            )
        steps.append("no rule matched")
        return Decision(
            allowed=False,
            reason="Denied by default: no allow rule matches this call",
            matched_rules=[],
            steps=steps,
        )

    def explain(self, call):
        """Explain mode: evaluate without executing; same result as evaluate."""
        decision = self.evaluate(call)
        decision.steps.insert(
            0,
            f"explaining {call.get('tool')}.{call.get('action')} "
            f"on {call.get('resource')!r} in {call.get('environment')!r}",
        )
        return decision
