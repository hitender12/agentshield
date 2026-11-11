"""AgentShield — a permission gateway for AI tools and MCP servers.

Reference implementation (Python 3 standard library only). The production
system in the blueprint is a Rust daemon + TypeScript MCP adapter; this
package is the auditable reference core: policy-as-code, default deny,
scoped secrets, human approval, budgets, and an append-only audit log.
"""

from .policy import Policy, Rule, PolicyError
from .engine import PolicyEngine, Decision
from .secrets import SecretBroker
from .approval import ApprovalStore
from .budget import Budget, BudgetManager
from .audit import AuditLog
from .gateway import Gateway, ToolCall

__all__ = [
    "Policy", "Rule", "PolicyError",
    "PolicyEngine", "Decision",
    "SecretBroker", "ApprovalStore",
    "Budget", "BudgetManager",
    "AuditLog", "Gateway", "ToolCall",
]

__version__ = "0.1.0"
