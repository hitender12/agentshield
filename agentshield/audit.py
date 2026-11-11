"""Audit log: append-only JSONL records (actor, tool, policy decision,
resource, timestamp, outcome). Configured secrets are redacted before a
record is written, so the log is safe to inspect and share.

Append-only means: records are only ever appended. This module never
rewrites, truncates, or deletes the file.

Tamper evidence: every entry carries ``prev_hash`` (the hash of the
previous entry) and ``hash`` (SHA-256 over the entry's canonical JSON
without the hash field itself), forming a hash chain from a fixed
genesis value. ``verify()`` recomputes the chain: flipping any field
of any retained entry, reordering entries, or deleting a middle entry
breaks the chain and is reported. Limits: deleting the *tail* of the
log, or the whole file, cannot be detected from the file alone — ship
the log to remote storage for that. ``verify()`` also never crashes on
a corrupt line: it reports it and keeps checking the rest.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from datetime import datetime, timezone

REQUIRED_FIELDS = ("ts", "run_id", "actor", "tool", "action", "resource",
                   "decision", "outcome", "prev_hash", "hash")

GENESIS_HASH = "0" * 64


def _entry_hash(entry):
    """SHA-256 over the entry's canonical JSON, excluding its own hash."""
    canonical = {k: v for k, v in entry.items() if k != "hash"}
    return hashlib.sha256(
        json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def new_run_id():
    """Unique id for one gateway run (never the constant ``run-1``)."""
    return f"run_{secrets.token_hex(8)}"


class AuditLog:
    def __init__(self, path, redact=None, run_id=None):
        """path: JSONL file. redact: callable(text) -> text (e.g. broker.redact).
        run_id: explicit id, or a fresh unique one when omitted."""
        self.path = path
        self.redact = redact or (lambda text: text)
        self.run_id = run_id or new_run_id()
        self._prev_hash = self._load_tail_hash()

    def _load_tail_hash(self):
        """Resume the hash chain when appending to an existing log file."""
        try:
            with open(self.path, encoding="utf-8") as fh:
                last = None
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        last = json.loads(line)
                    except json.JSONDecodeError:
                        last = None
                if isinstance(last, dict) and isinstance(last.get("hash"), str):
                    return last["hash"]
        except FileNotFoundError:
            pass
        return GENESIS_HASH

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
            "prev_hash": self._prev_hash,
        }
        entry["hash"] = _entry_hash(entry)
        self._prev_hash = entry["hash"]
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, sort_keys=True) + "\n")
        return entry

    def read(self):
        """Parsed entries; unparseable lines are skipped (see verify())."""
        entries = []
        try:
            with open(self.path, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        except FileNotFoundError:
            return []
        return entries

    def verify(self):
        """Check the file: valid JSONL, required fields, hash chain intact.

        Never raises for a corrupt file: corrupt lines, missing fields,
        and chain breaks are all reported as problems.
        """
        problems = []
        entries = 0
        expected_prev = GENESIS_HASH
        try:
            fh = open(self.path, encoding="utf-8")
        except FileNotFoundError:
            return {"entries": 0, "problems": [], "ok": True}
        with fh:
            for lineno, raw in enumerate(fh, start=1):
                line = raw.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    problems.append(f"line {lineno}: corrupt JSON (not valid JSONL)")
                    expected_prev = None  # chain continuity lost here
                    continue
                entries += 1
                if not isinstance(entry, dict):
                    problems.append(f"line {lineno}: entry is not an object")
                    expected_prev = None
                    continue
                missing = [f for f in REQUIRED_FIELDS if f not in entry]
                if missing:
                    problems.append(f"line {lineno}: missing {missing}")
                if expected_prev is not None:
                    if entry.get("prev_hash") != expected_prev:
                        problems.append(
                            f"line {lineno}: hash chain broken "
                            f"(prev_hash does not match previous entry)")
                if isinstance(entry.get("hash"), str):
                    if _entry_hash(entry) != entry["hash"]:
                        problems.append(
                            f"line {lineno}: entry hash mismatch "
                            f"(entry was modified after it was written)")
                    expected_prev = entry["hash"]
                else:
                    expected_prev = None
        return {"entries": entries, "problems": problems, "ok": not problems}
