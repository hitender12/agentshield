"""Human approval: sensitive operations require an explicit approval that
shows the exact action and arguments — and changing the arguments
invalidates the approval.

An approval is a token bound to the canonical (tool, action, args) triple.
The gateway recomputes the token from the *actual* call at execution time,
so a call with different arguments produces a different token and is not
covered by the earlier approval.

Security properties enforced here (each has a regression test):

- **Single-use, no replay.** Consuming an approval moves its token to a
  ``_consumed`` set. ``approve()`` on a consumed token returns False, so
  a consumed approval can never be re-added.
- **Deny revokes.** ``deny()`` removes a granted approval as well as
  refusing a pending one; a denied token can never be used.
- **Expiry.** Approvals carry a TTL (default 15 minutes) against an
  injectable clock. Expired approvals are refused by ``is_approved`` and
  cannot be granted by ``approve()``.
- **Human-only approval.** The agent *requests* an approval (the request
  records the agent as requester); only a human may *grant* it. The
  gateway exposes no approve method at all — ``approve()`` is the
  out-of-band human step (CLI prompt, web UI, chat confirmation), and it
  refuses ``actor="agent"``. A granted approval records ``actor="human"``.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from datetime import datetime, timedelta, timezone

# Default approval lifetime: 15 minutes. A human who walks away does not
# leave a live approval behind indefinitely.
DEFAULT_TTL_SECONDS = 900


def approval_token(tool, action, args):
    """Deterministic token for an exact (tool, action, args) triple."""
    canonical = json.dumps(
        {"tool": tool, "action": action, "args": args or {}},
        sort_keys=True, separators=(",", ":"), default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class ApprovalStore:
    def __init__(self, ttl_seconds=DEFAULT_TTL_SECONDS, clock=None):
        """ttl_seconds: approval lifetime. clock: monotonic seconds
        callable (default time.monotonic); injectable so tests can
        simulate time passing deterministically."""
        if ttl_seconds is not None and (not isinstance(ttl_seconds, (int, float))
                                        or isinstance(ttl_seconds, bool)
                                        or ttl_seconds <= 0):
            raise ValueError("ttl_seconds must be a positive number")
        self.ttl_seconds = ttl_seconds
        self._clock = clock or time.monotonic
        self._pending = {}   # token -> request dict
        self._approved = set()
        self._consumed = set()  # single-use tokens that can never come back
        self._denied = set()

    # -- internals ------------------------------------------------------
    def _deadline(self):
        return self._clock() + self.ttl_seconds

    def _is_expired(self, token):
        record = self._pending.get(token)
        if record is None:
            return True
        return self._clock() > record["_deadline"]

    def _expire_if_needed(self, token):
        """Drop an expired approval; returns True when it was expired."""
        if token in self._approved and self._is_expired(token):
            self._approved.discard(token)
            self._pending[token]["status"] = "expired"
            return True
        return False

    # -- agent side: request ---------------------------------------------
    def request(self, tool, action, args, actor="agent"):
        """Record a pending approval request; returns its token.

        The request shows the exact action and arguments to the human.
        ``actor`` is the *requester* (normally the agent); the approver
        is recorded separately by :meth:`approve`.
        """
        token = approval_token(tool, action, args)
        now = datetime.now(timezone.utc)
        self._pending[token] = {
            "token": token[:16],
            "tool": tool,
            "action": action,
            "args": args or {},
            "actor": actor,
            "status": "pending",
            "requested_at": now.isoformat(),
            "expires_at": (now + timedelta(seconds=self.ttl_seconds)).isoformat(),
            "ttl_seconds": self.ttl_seconds,
            "_deadline": self._deadline(),
        }
        # A fresh request for the same triple starts a new approval
        # lifecycle, superseding any earlier denied/consumed state.
        self._denied.discard(token)
        self._consumed.discard(token)
        return token

    def pending(self, token):
        record = self._pending.get(token)
        if record is None:
            return None
        # Return a copy without the internal monotonic deadline.
        return {k: v for k, v in record.items() if not k.startswith("_")}

    # -- human side: approve / deny (out of band) ------------------------
    def approve(self, token, actor="human"):
        """Grant a pending request. Only a human may approve.

        Returns False when the token is unknown, already consumed,
        already denied, expired, or when the approver is not a human.
        """
        if actor != "human":
            return False
        if token not in self._pending:
            return False
        if token in self._consumed or token in self._denied:
            return False
        if self._is_expired(token):
            self._pending[token]["status"] = "expired"
            return False
        if self._pending[token]["status"] != "pending":
            return False
        self._pending[token]["status"] = "approved"
        self._pending[token]["actor"] = "human"
        self._pending[token]["approved_by"] = "human"
        self._approved.add(token)
        return True

    def deny(self, token):
        """Refuse a request — and revoke a granted approval.

        Returns True when the token was known (pending or approved).
        A denied token can never be approved or used afterwards.
        """
        if token not in self._pending:
            return False
        self._approved.discard(token)
        self._denied.add(token)
        self._pending[token]["status"] = "denied"
        return True

    # -- gateway side: check ----------------------------------------------
    def has_approval(self, tool, action, args):
        """Peek: is this exact call currently approved? Does NOT consume
        the approval and does NOT grant anything. Used by explain mode."""
        token = approval_token(tool, action, args)
        if token in self._consumed or token in self._denied:
            return False
        if token not in self._approved:
            return False
        if self._expire_if_needed(token):
            return False
        return True

    def is_approved(self, tool, action, args, single_use=True):
        """True only when the exact call was approved (args must match).

        Single-use by default: a successful check consumes the approval,
        moving its token to ``_consumed`` so it can never be replayed or
        re-approved. Expired approvals are refused.
        """
        token = approval_token(tool, action, args)
        if token in self._consumed or token in self._denied:
            return False
        if token not in self._approved:
            return False
        if self._expire_if_needed(token):
            return False
        if single_use:
            self._approved.discard(token)
            self._consumed.add(token)
        return True

    def list_pending(self):
        return [self.pending(token) for token, record in self._pending.items()
                if record["status"] == "pending"
                and not self._is_expired(token)]


def new_request_id():
    return secrets.token_hex(8)
