"""Budgets and quotas: per-run tool-call count, wall-clock time, and cost
ceiling. Exceeding any of them blocks further calls.

Costs are charged per executed call (a call that was denied by policy or
refused for lack of approval is never charged). The clock is injectable so
tests can simulate time passing deterministically.
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

    def check(self, cost=0.0):
        """Return (ok, reason). Call before executing a tool call."""
        if self.blocked_reason:
            return False, self.blocked_reason
        if self.budget.max_calls is not None and self.calls >= self.budget.max_calls:
            self.blocked_reason = f"call budget exceeded: {self.calls}/{self.budget.max_calls} calls"
            return False, self.blocked_reason
        if self.budget.max_seconds is not None:
            elapsed = self._clock() - self._start
            if elapsed >= self.budget.max_seconds:
                self.blocked_reason = f"time budget exceeded: {elapsed:.1f}s/{self.budget.max_seconds}s"
                return False, self.blocked_reason
        if self.budget.max_cost is not None and self.cost + cost > self.budget.max_cost:
            self.blocked_reason = (
                f"cost budget exceeded: {self.cost + cost:.2f} would exceed "
                f"{self.budget.max_cost:.2f}")
            return False, self.blocked_reason
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
