"""Scoped secrets: a broker that hands a credential to the single action
that needs it, and a redactor that keeps secrets out of logs.

Rules enforced here:

- Secrets come only from the process environment (``AGENTSHIELD_SECRET_<NAME>``)
  or an explicitly supplied mapping — never from prompts or tool arguments.
- **Every configured secret is registered for redaction at construction**,
  whether or not it has been handed out yet. A secret that was never
  fetched can still leak through a tool's output or a file path, and the
  redactor must already know it.
- Redaction has no minimum-length exemption: even a short value is
  scrubbed (longest values first, so a short value that is a substring
  of a longer one cannot partially unmask it).
- **Default deny for unscoped secrets.** A secret with no
  ``secret_scopes`` entry is handed to *no* tool. Access must be
  granted explicitly, per secret, per tool.
"""

from __future__ import annotations

import os

PREFIX = "AGENTSHIELD_SECRET_"


class SecretBroker:
    def __init__(self, scopes=None, source=None):
        """scopes: {secret_name: [tool, ...]}. source: mapping (default: os.environ).

        All ``AGENTSHIELD_SECRET_*`` values present in ``source`` are
        registered for redaction immediately.
        """
        self.scopes = {k: list(v) for k, v in (scopes or {}).items()}
        self.source = dict(source) if source is not None else dict(os.environ)
        self._seen = {}  # name -> value, for redaction
        for key, value in self.source.items():
            if key.startswith(PREFIX) and value:
                self._seen[key[len(PREFIX):]] = value

    def get(self, name, tool):
        """Return the secret for ``name`` only if ``tool`` is in scope.

        Returns ``None`` when the secret is missing, when the tool is out
        of scope, and — by default — when the secret has no scope entry
        at all. The caller must never put the returned value into a
        prompt, log line, or tool argument visible to the model.
        """
        allowed_tools = self.scopes.get(name)
        if allowed_tools is None:
            # Unscoped secret: deny by default. Grant access explicitly
            # in the policy's secret_scopes, never by omission.
            return None
        if tool not in allowed_tools:
            return None
        value = self.source.get(PREFIX + name)
        if value is None:
            return None
        self._seen[name] = value
        return value

    def known_secrets(self):
        """{name: value} for every secret configured in the source."""
        return dict(self._seen)

    def redact(self, text):
        """Replace every known secret value in ``text`` with ``[REDACTED]``.

        No minimum-length exemption: any configured value is scrubbed,
        longest first.
        """
        if not isinstance(text, str):
            text = str(text)
        for name, value in sorted(self._seen.items(),
                                  key=lambda item: -len(item[1])):
            if value and value in text:
                text = text.replace(value, f"[REDACTED:{name}]")
        return text
