"""Audit log: append-only JSONL records (actor, tool, policy decision,
resource, timestamp, outcome). Configured secrets are redacted before a
record is written, so the log is safe to inspect and share.

Append-only means: records are only ever appended. This module never
rewrites, truncates, or deletes the file. ``verify()`` checks every line
parses as JSON and carries the required fields.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

REQUIRED_FIELDS = ("ts", "actor", "tool", "action", "resource",
                   "decision", "outcome")


class AuditLog:
    def __init__(self, path, redact=None, run_id="run-1"):
        """path: JSONL file. redact: callable(text) -> text (e.g. broker.redact)."""
        self.path = path
        self.redact = redact or (lambda text: text)
        self.run_id = run_id

    def record(self, actor, tool, action, resource, decision, outcome, detail=""):
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "run_id": self.run_id,
            "actor": actor,
            "tool": tool,
            "action": action,
            "resource": self.redact(str(resource)),
            "decision": decision,
            "outcome": outcome,
            "detail": self.redact(str(detail)),
        }
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, sort_keys=True) + "\n")
        return entry

    def read(self):
        entries = []
        try:
            with open(self.path, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        entries.append(json.loads(line))
        except FileNotFoundError:
            return []
        return entries

    def verify(self):
        """Check the file is intact JSONL with all required fields."""
        entries = self.read()
        problems = []
        for i, entry in enumerate(entries):
            missing = [f for f in REQUIRED_FIELDS if f not in entry]
            if missing:
                problems.append(f"line {i + 1}: missing {missing}")
        return {"entries": len(entries), "problems": problems, "ok": not problems}
