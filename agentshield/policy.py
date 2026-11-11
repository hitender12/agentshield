"""Policy-as-code: readable rules for tools, users, projects, environments,
resources, and actions.

Policies load from JSON, or from a small YAML subset (documented below).
Every rule field is optional; an omitted field matches anything. Patterns
use glob syntax (``*`` and ``?``) via :mod:`fnmatch`.

YAML subset supported (deliberately small — this is NOT a full YAML parser):
- ``key: value`` pairs (strings, ints, floats, booleans, null)
- nested mappings by indentation
- lists with ``- item`` and ``- key: value`` (list of maps)
- ``#`` full-line comments, and `` #`` trailing comments outside quotes
- single- and double-quoted strings

Anything outside that subset raises :class:`PolicyError`. Do not feed this
reader arbitrary YAML and expect it to work; use JSON for complex policies.
"""

from __future__ import annotations

import fnmatch
import json

MATCH_FIELDS = ("tool", "action", "resource", "environment", "user", "project")


class PolicyError(ValueError):
    """Raised when a policy file is malformed or fails validation."""


class Rule:
    """One allow/deny rule. All specified fields must match (glob)."""

    def __init__(self, rule_id, effect, tool=None, action=None, resource=None,
                 environment=None, user=None, project=None):
        if effect not in ("allow", "deny"):
            raise PolicyError(f"rule {rule_id!r}: effect must be 'allow' or 'deny', got {effect!r}")
        self.id = rule_id
        self.effect = effect
        self.tool = tool
        self.action = action
        self.resource = resource
        self.environment = environment
        self.user = user
        self.project = project

    def matches(self, call):
        """True when every specified field glob-matches the call."""
        for field in MATCH_FIELDS:
            pattern = getattr(self, field)
            if pattern is None:
                continue
            value = str(call.get(field, "") or "")
            if not fnmatch.fnmatchcase(value, pattern):
                return False
        return True

    def describe(self):
        parts = [f"{f}={getattr(self, f)}" for f in MATCH_FIELDS if getattr(self, f)]
        return f"{self.id} [{self.effect}] " + (", ".join(parts) or "matches everything")

    @classmethod
    def from_dict(cls, data):
        if not isinstance(data, dict):
            raise PolicyError(f"rule must be a mapping, got {data!r}")
        try:
            rule_id = data["id"]
            effect = data["effect"]
        except KeyError as exc:
            raise PolicyError(f"rule missing required field: {exc}") from exc
        unknown = set(data) - {"id", "effect"} - set(MATCH_FIELDS)
        if unknown:
            raise PolicyError(f"rule {rule_id!r}: unknown fields {sorted(unknown)}")
        return cls(rule_id, effect, **{f: data.get(f) for f in MATCH_FIELDS})


class Policy:
    """A versioned set of rules plus gateway settings."""

    def __init__(self, name, rules, sensitive_actions=(), budgets=None,
                 secret_scopes=None, version=1):
        self.name = name
        self.version = version
        self.rules = list(rules)
        self.sensitive_actions = tuple(sensitive_actions)
        self.budgets = dict(budgets or {})
        self.secret_scopes = {k: list(v) for k, v in (secret_scopes or {}).items()}

    def is_sensitive(self, action):
        return action in self.sensitive_actions

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------
    @classmethod
    def from_dict(cls, data):
        if not isinstance(data, dict):
            raise PolicyError("policy must be a mapping")
        if "rules" not in data or not isinstance(data["rules"], list):
            raise PolicyError("policy must contain a 'rules' list")
        rules = [Rule.from_dict(r) for r in data["rules"]]
        ids = [r.id for r in rules]
        if len(set(ids)) != len(ids):
            raise PolicyError(f"duplicate rule ids: {ids}")
        return cls(
            name=data.get("name", "unnamed"),
            rules=rules,
            sensitive_actions=data.get("sensitive_actions", ()),
            budgets=data.get("budgets", {}),
            secret_scopes=data.get("secret_scopes", {}),
            version=data.get("version", 1),
        )

    @classmethod
    def from_json(cls, text):
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise PolicyError(f"invalid JSON policy: {exc}") from exc
        return cls.from_dict(data)

    @classmethod
    def from_json_file(cls, path):
        with open(path, encoding="utf-8") as fh:
            return cls.from_json(fh.read())

    @classmethod
    def from_yaml_subset(cls, text):
        return cls.from_dict(_parse_yaml_subset(text))

    @classmethod
    def from_yaml_subset_file(cls, path):
        with open(path, encoding="utf-8") as fh:
            return cls.from_yaml_subset(fh.read())


# ----------------------------------------------------------------------
# Minimal YAML-subset parser
# ----------------------------------------------------------------------

def _strip_comment(line):
    """Remove a `` #`` comment outside quotes; keep ``#`` inside quotes."""
    in_single = in_double = False
    for i, ch in enumerate(line):
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double and i > 0 and line[i - 1] == " ":
            return line[:i].rstrip()
    return line.rstrip()


def _scalar(token):
    token = token.strip()
    if len(token) >= 2 and token[0] == token[-1] and token[0] in ("'", '"'):
        return token[1:-1]
    if token in ("true", "True"):
        return True
    if token in ("false", "False"):
        return False
    if token in ("null", "~", ""):
        return None
    try:
        return int(token)
    except ValueError:
        pass
    try:
        return float(token)
    except ValueError:
        pass
    return token


def _parse_yaml_subset(text):
    lines = []
    for raw in text.splitlines():
        line = _strip_comment(raw)
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        if "\t" in line[:indent]:
            raise PolicyError("YAML subset: tabs are not allowed for indentation")
        lines.append((indent, line.strip()))
    if not lines:
        raise PolicyError("YAML subset: empty document")
    parsed, _ = _parse_block(lines, 0, lines[0][0])
    if not isinstance(parsed, dict):
        raise PolicyError("YAML subset: top level must be a mapping")
    return parsed


def _parse_block(lines, pos, indent):
    """Parse a mapping or list block starting at lines[pos] with given indent."""
    if lines[pos][1].startswith("- ") or lines[pos][1] == "-":
        return _parse_list(lines, pos, indent)
    mapping = {}
    while pos < len(lines):
        ind, content = lines[pos]
        if ind < indent:
            break
        if ind > indent:
            raise PolicyError(f"YAML subset: unexpected indent at line: {content!r}")
        if content.startswith("- "):
            raise PolicyError(f"YAML subset: list item inside mapping at: {content!r}")
        if ":" not in content:
            raise PolicyError(f"YAML subset: expected 'key: value', got: {content!r}")
        key, _, rest = content.partition(":")
        key = key.strip()
        rest = rest.strip()
        if rest:
            mapping[key] = _scalar(rest)
            pos += 1
        else:
            pos += 1
            if pos >= len(lines) or lines[pos][0] <= indent:
                mapping[key] = None
            else:
                value, pos = _parse_block(lines, pos, lines[pos][0])
                mapping[key] = value
    return mapping, pos


def _parse_list(lines, pos, indent):
    items = []
    while pos < len(lines):
        ind, content = lines[pos]
        if ind < indent or not (content.startswith("- ") or content == "-"):
            break
        if ind > indent:
            raise PolicyError(f"YAML subset: unexpected indent in list at: {content!r}")
        item_text = content[1:].strip()
        if not item_text:
            pos += 1
            if pos < len(lines) and lines[pos][0] > indent:
                value, pos = _parse_block(lines, pos, lines[pos][0])
                items.append(value)
            else:
                items.append(None)
            continue
        if ":" in item_text and not item_text.startswith(('"', "'")):
            # A mapping starting on the dash line: "- key: value" plus
            # continuation keys indented to the dash content column.
            key, _, rest = item_text.partition(":")
            item = {key.strip(): _scalar(rest.strip()) if rest.strip() else None}
            pos += 1
            cont_indent = ind + 2
            while pos < len(lines) and lines[pos][0] == cont_indent and ":" in lines[pos][1]:
                k, _, v = lines[pos][1].partition(":")
                item[k.strip()] = _scalar(v.strip()) if v.strip() else None
                pos += 1
            items.append(item)
        else:
            items.append(_scalar(item_text))
            pos += 1
    return items, pos
