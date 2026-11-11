"""Scoped secrets: a broker that hands a credential to the single action
that needs it, and a redactor that keeps secrets out of logs.

Rules enforced here:
- Secrets come only from the process environment (``AGENTSHIELD_SECRET_<NAME>``)
  or an explicitly supplied mapping — never from prompts or tool arguments.
- A secret is handed out only when the requesting tool is in that secret's
  scope list in the policy (``secret_scopes``).
- Every value the broker has seen is registered for redaction, so the audit
  writer can scrub it from any recorded text.
"""

from __future__ import annotations

import os

PREFIX = "AGENTSHIELD_SECRET_"


class SecretBroker:
    def __init__(self, scopes=None, source=None):
        """scopes: {secret_name: [tool, ...]}. source: mapping (default: os.environ)."""
        self.scopes = {k: list(v) for k, v in (scopes or {}).items()}
        self.source = dict(source) if source is not None else dict(os.environ)
        self._seen = {}  # name -> value, for redaction

    def get(self, name, tool):
        """Return the secret for ``name`` only if ``tool`` is in scope.

        Returns ``None`` when the secret is missing or the tool is out of scope.
        The caller must never put the returned value into a prompt, log line,
        or tool argument visible to the model.
        """
        allowed_tools = self.scopes.get(name)
        if allowed_tools is not None and tool not in allowed_tools:
            return None
        value = self.source.get(PREFIX + name)
        if value is None:
            return None
        self._seen[name] = value
        return value

    def known_secrets(self):
        """{name: value} for every secret value handed out so far."""
        return dict(self._seen)

    def redact(self, text):
        """Replace every known secret value in ``text`` with ``[REDACTED]``."""
        if not isinstance(text, str):
            text = str(text)
        for name, value in self._seen.items():
            if value and len(value) >= 4 and value in text:
                text = text.replace(value, f"[REDACTED:{name}]")
        return text
