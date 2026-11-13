"""Fake tools the demo gateway routes to.

These are deliberately small and local: a file tool scoped to one base
directory, and a fake database with a staging and a production dataset.
Real deployments would route to MCP servers; the gateway does not care —
it enforces policy before the tool ever runs.
"""

from __future__ import annotations

import os

TOOL_COSTS = {
    ("files", "list"): 0.0,
    ("files", "read"): 0.01,
    ("files", "delete"): 0.05,
    ("deploy", "run"): 0.50,
    ("db", "query"): 0.02,
}


class ToolError(Exception):
    pass


class FakeTools:
    """Tools bound to a workspace directory and a fake two-environment DB."""

    def __init__(self, base_dir):
        self.base_dir = os.path.abspath(base_dir)
        self.db = {
            "staging": {"users": 12, "orders": 48},
            "prod": {"users": 10432, "orders": 98120},
        }

    # -- path safety: a tool may only touch paths inside base_dir --------
    def _safe_path(self, rel):
        if not isinstance(rel, str):
            raise ToolError(
                f"path must be a string, got {type(rel).__name__}")
        # realpath (not abspath) resolves every symlink component, so a
        # symlink inside the workspace that points outside it is caught
        # here instead of being followed into the outside file. The
        # containment check runs on the *resolved* path.
        target = os.path.realpath(os.path.join(self.base_dir, rel or "."))
        if target != self.base_dir and not target.startswith(self.base_dir + os.sep):
            raise ToolError(f"path escapes workspace: {rel!r}")
        return target

    def files_list(self, args):
        path = self._safe_path(args.get("path", "."))
        try:
            if not os.path.isdir(path):
                raise ToolError(f"not a directory: {args.get('path')!r}")
            return sorted(os.listdir(path))
        except OSError as exc:
            raise ToolError(f"cannot list {args.get('path')!r}: {exc}") from exc

    def files_read(self, args):
        path = self._safe_path(args.get("path", ""))
        if not os.path.isfile(path):
            raise ToolError(f"not a file: {args.get('path')!r}")
        try:
            with open(path, encoding="utf-8") as fh:
                return fh.read()
        except UnicodeDecodeError:
            # A binary file must be a ToolError (denied/errored by the
            # gateway), never an uncaught decode crash.
            raise ToolError(f"not valid UTF-8 text: {args.get('path')!r}")
        except OSError as exc:
            raise ToolError(f"cannot read {args.get('path')!r}: {exc}") from exc

    def files_delete(self, args):
        path = self._safe_path(args.get("path", ""))
        if not os.path.isfile(path):
            raise ToolError(f"not a file: {args.get('path')!r}")
        try:
            os.remove(path)
        except OSError as exc:
            raise ToolError(f"cannot delete {args.get('path')!r}: {exc}") from exc
        return f"deleted {args.get('path')}"

    def deploy_run(self, args):
        env = args.get("environment", "")
        return f"deployed {args.get('service', 'app')} to {env}"

    def db_query(self, args, secret=None):
        env = args.get("environment", "")
        table = args.get("table", "")
        if not isinstance(env, str) or not isinstance(table, str):
            raise ToolError("db query needs string environment and table")
        data = self.db.get(env, {})
        if table not in data:
            raise ToolError(f"no table {table!r} in {env!r}")
        # `secret` is accepted (a scoped DB credential) but never logged
        # or echoed back; it only proves the broker handed it to this call.
        # It does NOT gate data access: rows are returned with
        # authenticated False when no credential was configured (see
        # THREAT_MODEL.md). Real deployments must enforce authentication
        # in the tool/MCP server itself.
        return {"environment": env, "table": table, "rows": data[table],
                "authenticated": secret is not None}

    def dispatch(self, tool, action, args, secret=None):
        if not isinstance(tool, str) or not isinstance(action, str):
            raise ToolError("tool and action must be strings")
        if not isinstance(args, dict):
            raise ToolError("args must be a mapping")
        handlers = {
            ("files", "list"): lambda: self.files_list(args),
            ("files", "read"): lambda: self.files_read(args),
            ("files", "delete"): lambda: self.files_delete(args),
            ("deploy", "run"): lambda: self.deploy_run(args),
            ("db", "query"): lambda: self.db_query(args, secret=secret),
        }
        handler = handlers.get((tool, action))
        if handler is None:
            raise ToolError(f"unknown tool action: {tool}.{action}")
        return handler()
