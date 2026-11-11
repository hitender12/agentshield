"""Human approval: sensitive operations require an explicit approval that
shows the exact action and arguments — and changing the arguments
invalidates the approval.

An approval is a token bound to the canonical (tool, action, args) triple.
The gateway recomputes the token from the *actual* call at execution time,
so a call with different arguments produces a different token and is not
covered by the earlier approval. Approvals are single-use by default.
"""

from __future__ import annotations

import hashlib
import json
import secrets


def approval_token(tool, action, args):
    """Deterministic token for an exact (tool, action, args) triple."""
    canonical = json.dumps(
        {"tool": tool, "action": action, "args": args or {}},
        sort_keys=True, separators=(",", ":"), default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class ApprovalStore:
    def __init__(self):
        self._pending = {}   # token -> request dict
        self._approved = set()

    def request(self, tool, action, args, actor="human"):
        """Record a pending approval request; returns its token.

        The request shows the exact action and arguments to the human.
        """
        token = approval_token(tool, action, args)
        self._pending[token] = {
            "token": token[:16],
            "tool": tool,
            "action": action,
            "args": args or {},
            "actor": actor,
            "status": "pending",
        }
        return token

    def pending(self, token):
        return self._pending.get(token)

    def approve(self, token):
        """Approve a pending request. Returns True if it was pending."""
        if token in self._pending:
            self._pending[token]["status"] = "approved"
            self._approved.add(token)
            return True
        return False

    def deny(self, token):
        if token in self._pending:
            self._pending[token]["status"] = "denied"
            return True
        return False

    def is_approved(self, tool, action, args, single_use=True):
        """True only when the exact call was approved (args must match)."""
        token = approval_token(tool, action, args)
        if token not in self._approved:
            return False
        if single_use:
            self._approved.discard(token)
        return True

    def list_pending(self):
        return [r for r in self._pending.values() if r["status"] == "pending"]


def new_request_id():
    return secrets.token_hex(8)
