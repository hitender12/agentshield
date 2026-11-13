"""Budgets and quotas: per-run tool-call count, wall-clock time, and cost
ceiling. Exceeding any of them blocks further calls.

Costs are charged per *attempted* call: once the budget check passes,
the attempt is recorded immediately, whether environment agreement,
policy, approval, or the tool itself then refuses it. The gateway runs
the budget gate *first*, so environment-mismatched and malformed calls
cannot loop for free either. Denied and erroring calls cannot loop for
free. The clock is injectable so tests can simulate time passing
deterministically.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field


@dataclass
class Budget:
    max_calls: int | None = None
    max_seconds: float | None = None
    max_cost: float | None = None


class BudgetManager:
    def __init__(self, budget, clock=None):
        self.budget = budget or Budget()
        self._clock = clock or time.monotonic
        self._start = self._clock()
        self.calls = 0
        self.cost = 0.0
        self.blocked_reason = None

    def _violation(self, cost=0.0):
        """Reason this call would exceed a budget, or None if within limits.

        Pure check: never latches, never records. ``check()`` latches on
        failure; :meth:`would_allow` uses this directly.
        """
        if self.blocked_reason:
            return self.blocked_reason
        if self.budget.max_calls is not None and self.calls >= self.budget.max_calls:
            return f"call budget exceeded: {self.calls}/{self.budget.max_calls} calls"
        if self.budget.max_seconds is not None:
            elapsed = self._clock() - self._start
            if elapsed >= self.budget.max_seconds:
                return f"time budget exceeded: {elapsed:.1f}s/{self.budget.max_seconds}s"
        if self.budget.max_cost is not None and self.cost + cost > self.budget.max_cost:
            return (f"cost budget exceeded: {self.cost + cost:.2f} would exceed "
                    f"{self.budget.max_cost:.2f}")
        return None

    def would_allow(self, cost=0.0):
        """Non-latching probe: would this call fit the budget?

        Used by explain mode, which must never consume budget or latch a
        block as a side effect of asking.
        """
        reason = self._violation(cost)
        return (reason is None, reason or "within budget")

    def check(self, cost=0.0):
        """Return (ok, reason). Call before executing a tool call."""
        reason = self._violation(cost)
        if reason is not None:
            self.blocked_reason = reason
            return False, reason
        return True, "within budget"

    def record(self, cost=0.0):
        self.calls += 1
        self.cost += cost

    def remaining(self):
        return {
            "calls_used": self.calls,
            "calls_left": (None if self.budget.max_calls is None
                           else max(0, self.budget.max_calls - self.calls)),
            "cost_used": round(self.cost, 4),
            "cost_left": (None if self.budget.max_cost is None
                          else round(max(0.0, self.budget.max_cost - self.cost), 4)),
            "elapsed_seconds": round(self._clock() - self._start, 3),
        }
