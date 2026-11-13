"""Policy-as-code: readable rules for tools, users, projects, environments,
resources, and actions.

Policies load from JSON, or from a small YAML subset (documented below).
Every rule field is optional; an omitted field matches anything. Patterns
use glob syntax (``*`` and ``?``) via :mod:`fnmatch`.

YAML subset supported (deliberately small — this is NOT a full YAML parser):
- ``key: value`` pairs (strings, ints, floats, booleans, null)
- nested mappings by indentation (at most ``MAX_YAML_DEPTH`` levels)
- lists with ``- item`` and ``- key: value`` (list of maps)
- flow collections: ``[a, b]`` and ``{k: v}`` (parsed, not left as strings)
- ``#`` full-line comments, and `` #`` trailing comments outside quotes
- single- and double-quoted strings
- duplicate mapping keys are rejected (last-win would silently change
  the policy)

Rejected outright with :class:`PolicyError` (never silently
misinterpreted): anchors (``&name``), aliases (``*name``), tags
(``!tag``), block scalars (``|``/``>``), document markers (``---``/``...``),
tabs for indentation, duplicate keys, unbalanced flow collections, and
nesting deeper than ``MAX_YAML_DEPTH``. Anything outside that subset
raises :class:`PolicyError`. Do not feed this reader arbitrary YAML and
expect it to work; use JSON for complex policies.
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
        if not isinstance(rule_id, str) or not rule_id:
            raise PolicyError(f"rule id must be a non-empty string, got {rule_id!r}")
        if not isinstance(effect, str):
            raise PolicyError(f"rule {rule_id!r}: effect must be a string, got {effect!r}")
        unknown = set(data) - {"id", "effect"} - set(MATCH_FIELDS)
        if unknown:
            raise PolicyError(f"rule {rule_id!r}: unknown fields {sorted(unknown)}")
        for field in MATCH_FIELDS:
            value = data.get(field)
            if value is not None and not isinstance(value, str):
                raise PolicyError(
                    f"rule {rule_id!r}: field {field!r} must be a string "
                    f"glob pattern, got {type(value).__name__} {value!r}")
        return cls(rule_id, effect, **{f: data.get(f) for f in MATCH_FIELDS})


class Policy:
    """A versioned set of rules plus gateway settings."""

    def __init__(self, name, rules, sensitive_actions=(), budgets=None,
                 secret_scopes=None, version=1):
        if not isinstance(name, str):
            raise PolicyError(f"policy name must be a string, got {name!r}")
        if not isinstance(version, int) or isinstance(version, bool):
            raise PolicyError(f"policy version must be an integer, got {version!r}")
        if isinstance(sensitive_actions, str) or not isinstance(
                sensitive_actions, (list, tuple)):
            raise PolicyError(
                "sensitive_actions must be a list of action names, "
                f"got {sensitive_actions!r} — a bare string would be read "
                "as single characters and silently disable approvals")
        for action in sensitive_actions:
            if not isinstance(action, str):
                raise PolicyError(
                    f"sensitive_actions must contain strings, got {action!r}")
        if budgets is not None and not isinstance(budgets, dict):
            raise PolicyError(f"budgets must be a mapping, got {budgets!r}")
        for key, value in (budgets or {}).items():
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                raise PolicyError(
                    f"budgets[{key!r}] must be a number, got {value!r}")
        if secret_scopes is not None and not isinstance(secret_scopes, dict):
            raise PolicyError(
                f"secret_scopes must be a mapping, got {secret_scopes!r}")
        for secret, tools in (secret_scopes or {}).items():
            if isinstance(tools, str) or not isinstance(tools, (list, tuple)):
                raise PolicyError(
                    f"secret_scopes[{secret!r}] must be a list of tool names, "
                    f"got {tools!r} — a bare string would be read as single "
                    "characters and silently break scoping")
            for tool in tools:
                if not isinstance(tool, str):
                    raise PolicyError(
                        f"secret_scopes[{secret!r}] must contain strings, "
                        f"got {tool!r}")
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
        if not data["rules"]:
            raise PolicyError("policy must contain at least one rule")
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


# Maximum YAML nesting depth. Policies are shallow (a handful of
# levels); anything deeper is treated as a hostile or broken document
# rather than recursed into — without this, ~1000 nested levels raise
# RecursionError instead of PolicyError.
MAX_YAML_DEPTH = 32


def _check_key(key):
    """Reject YAML constructs that must never appear as a mapping key."""
    if key and key[0] in "&*!":
        raise PolicyError(
            f"YAML subset: anchors, aliases and tags are not supported: {key!r}")
    return key


def _split_flow(inner):
    """Split a flow-collection body on top-level commas.

    Respects quotes and nesting, so ``[a, "b, c", [d, e]]`` splits into
    three items. Returns the raw item strings (still to be scalar-parsed).
    """
    parts, depth, in_single, in_double, current = [], 0, False, False, ""
    for ch in inner:
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif not in_single and not in_double:
            if ch in "[{":
                depth += 1
            elif ch in "]}":
                depth -= 1
                if depth < 0:
                    raise PolicyError("YAML subset: unbalanced brackets in flow collection")
            elif ch == "," and depth == 0:
                parts.append(current)
                current = ""
                continue
        current += ch
    if depth != 0:
        raise PolicyError("YAML subset: unbalanced brackets in flow collection")
    parts.append(current)
    return [part.strip() for part in parts if part.strip()]


def _parse_flow(token, depth=0):
    """Parse a flow collection token: ``[a, b]`` or ``{k: v, ...}``."""
    if depth > MAX_YAML_DEPTH:
        raise PolicyError(
            f"YAML subset: nesting deeper than {MAX_YAML_DEPTH} levels")
    if token.startswith("[") and token.endswith("]"):
        return [_scalar(item, depth + 1) for item in _split_flow(token[1:-1])]
    if token.startswith("{") and token.endswith("}"):
        mapping = {}
        for item in _split_flow(token[1:-1]):
            if ":" not in item:
                raise PolicyError(
                    f"YAML subset: expected 'key: value' in flow mapping, got {item!r}")
            key, _, rest = item.partition(":")
            key = _check_key(key.strip())
            if key in mapping:
                raise PolicyError(f"YAML subset: duplicate key {key!r}")
            mapping[key] = _scalar(rest.strip(), depth + 1)
        return mapping
    raise PolicyError(f"YAML subset: malformed flow collection {token!r}")


def _scalar(token, depth=0):
    token = token.strip()
    if len(token) >= 2 and token[0] == token[-1] and token[0] in ("'", '"'):
        return token[1:-1]
    # Anchors, aliases and tags are YAML constructs this subset does not
    # implement: an unquoted ``&a``, ``*x`` or ``!tag`` must be rejected,
    # not read as the literal string (a ``*x`` tool name would otherwise
    # silently become the glob "*x"). Quoted values were handled above,
    # so a quoted '*' stays a legal glob.
    if token.startswith(("&", "*", "!")):
        raise PolicyError(
            f"YAML subset: anchors, aliases and tags are not supported: {token!r}")
    # Block scalars and document markers are likewise unsupported.
    if token.startswith(("|", ">")) or token in ("---", "..."):
        raise PolicyError(f"YAML subset: unsupported construct: {token!r}")
    if token in ("true", "True"):
        return True
    if token in ("false", "False"):
        return False
    if token in ("null", "~", ""):
        return None
    if token.startswith("[") or token.startswith("{"):
        # Flow collection. A token that opens but never closes is a
        # syntax error, not a plain string.
        if (token.startswith("[") and token.endswith("]")) or \
                (token.startswith("{") and token.endswith("}")):
            return _parse_flow(token, depth)
        raise PolicyError(f"YAML subset: unbalanced flow collection {token!r}")
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
    parsed, _ = _parse_block(lines, 0, lines[0][0], depth=0)
    if not isinstance(parsed, dict):
        raise PolicyError("YAML subset: top level must be a mapping")
    return parsed


def _parse_block(lines, pos, indent, depth=0):
    """Parse a mapping or list block starting at lines[pos] with given indent."""
    if depth > MAX_YAML_DEPTH:
        raise PolicyError(
            f"YAML subset: nesting deeper than {MAX_YAML_DEPTH} levels")
    if lines[pos][1].startswith("- ") or lines[pos][1] == "-":
        return _parse_list(lines, pos, indent, depth)
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
        key = _check_key(key.strip())
        if key in mapping:
            raise PolicyError(f"YAML subset: duplicate key {key!r}")
        rest = rest.strip()
        if rest:
            mapping[key] = _scalar(rest, depth + 1)
            pos += 1
        else:
            pos += 1
            if pos >= len(lines) or lines[pos][0] <= indent:
                mapping[key] = None
            else:
                value, pos = _parse_block(lines, pos, lines[pos][0], depth + 1)
                mapping[key] = value
    return mapping, pos


def _parse_list(lines, pos, indent, depth=0):
    if depth > MAX_YAML_DEPTH:
        raise PolicyError(
            f"YAML subset: nesting deeper than {MAX_YAML_DEPTH} levels")
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
                value, pos = _parse_block(lines, pos, lines[pos][0], depth + 1)
                items.append(value)
            else:
                items.append(None)
            continue
        if ":" in item_text and not item_text.startswith(('"', "'")):
            # A mapping starting on the dash line: "- key: value" plus
            # continuation keys indented to the dash content column.
            key, _, rest = item_text.partition(":")
            item = {_check_key(key.strip()): _scalar(rest.strip(), depth + 1) if rest.strip() else None}
            pos += 1
            cont_indent = ind + 2
            while pos < len(lines) and lines[pos][0] == cont_indent and ":" in lines[pos][1]:
                k, _, v = lines[pos][1].partition(":")
                k = _check_key(k.strip())
                if k in item:
                    raise PolicyError(f"YAML subset: duplicate key {k!r}")
                item[k] = _scalar(v.strip(), depth + 1) if v.strip() else None
                pos += 1
            items.append(item)
        else:
            items.append(_scalar(item_text, depth + 1))
            pos += 1
    return items, pos
