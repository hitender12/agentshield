"""Edge-case tests for AgentShield: policy decision table, approval
expiry, budget boundaries, path-escape attempts, and YAML-subset limits.

Run: python3 -m unittest discover -s tests
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agentshield import (  # noqa: E402
    ApprovalStore, AuditLog, Budget, BudgetManager, Gateway, Policy,
    PolicyError, SecretBroker, ToolCall,
)
from agentshield.engine import PolicyEngine  # noqa: E402
from agentshield.tools import FakeTools, ToolError  # noqa: E402

POLICY_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          "policies", "examples")


def load_demo_policy():
    return Policy.from_json_file(os.path.join(POLICY_DIR, "demo-policy.json"))


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


# A policy that exercises every match dimension: tool, action,
# resource (glob), environment, user, and project.
EDGE_POLICY = Policy.from_dict({
    "name": "edge-table",
    "rules": [
        {"id": "allow-files-list", "effect": "allow", "tool": "files",
         "action": "list", "resource": "workspace/*"},
        {"id": "allow-files-read", "effect": "allow", "tool": "files",
         "action": "read", "resource": "workspace/*"},
        {"id": "deny-files-delete-bob", "effect": "deny", "tool": "files",
         "action": "delete", "resource": "workspace/*", "user": "bob"},
        {"id": "allow-files-delete-alice", "effect": "allow", "tool": "files",
         "action": "delete", "resource": "workspace/*", "user": "alice"},
        {"id": "allow-db-staging", "effect": "allow", "tool": "db",
         "action": "query", "resource": "staging.*", "environment": "staging"},
        {"id": "deny-db-prod", "effect": "deny", "tool": "db",
         "action": "query", "resource": "prod.*", "environment": "prod"},
        {"id": "allow-deploy-staging", "effect": "allow", "tool": "deploy",
         "action": "run", "resource": "staging", "environment": "staging"},
        {"id": "deny-deploy-prod", "effect": "deny", "tool": "deploy",
         "action": "run", "resource": "prod", "environment": "prod"},
        {"id": "allow-issues-read-demo", "effect": "allow", "tool": "issues",
         "action": "read", "resource": "*", "project": "demo"},
    ],
})


def base_call(**overrides):
    call = {"tool": "files", "action": "read", "resource": "workspace/notes.txt",
            "environment": "staging", "user": "dev", "project": "demo"}
    call.update(overrides)
    return call


class TestPolicyDecisionTable(unittest.TestCase):
    """25-case decision table across tools, actions, environments,
    users, projects, and resources (glob, case, empty)."""

    CASES = [
        # (call kwargs, expected allowed, reason fragment)
        ({"tool": "files", "action": "list", "resource": "workspace/."},
         True, "allow-files-list"),
        ({"tool": "files", "action": "read", "resource": "workspace/notes.txt"},
         True, "allow-files-read"),
        # '*' crosses '/' in fnmatch: a nested workspace path still matches.
        ({"tool": "files", "action": "read", "resource": "workspace/deep/nested.txt"},
         True, "allow-files-read"),
        # 'workspace/*' must not match a sibling directory 'workspace2/'.
        ({"tool": "files", "action": "read", "resource": "workspace2/notes.txt"},
         False, "default"),
        ({"tool": "files", "action": "read", "resource": "/etc/passwd"},
         False, "default"),
        ({"tool": "files", "action": "write", "resource": "workspace/x"},
         False, "default"),
        # User dimension: only alice may delete; bob is explicitly denied.
        ({"tool": "files", "action": "delete", "resource": "workspace/x",
          "user": "alice"}, True, "allow-files-delete-alice"),
        ({"tool": "files", "action": "delete", "resource": "workspace/x",
          "user": "bob"}, False, "deny-files-delete-bob"),
        ({"tool": "files", "action": "delete", "resource": "workspace/x",
          "user": "carol"}, False, "default"),
        # Omitted rule fields match anything: user/project do not matter
        # for the unconstrained files-read rule.
        ({"tool": "files", "action": "read", "resource": "workspace/notes.txt",
          "user": "mallory", "project": "other"}, True, "allow-files-read"),
        ({"tool": "db", "action": "query", "resource": "staging.users",
          "environment": "staging"}, True, "allow-db-staging"),
        ({"tool": "db", "action": "query", "resource": "staging.orders",
          "environment": "staging"}, True, "allow-db-staging"),
        ({"tool": "db", "action": "query", "resource": "prod.users",
          "environment": "prod"}, False, "deny-db-prod"),
        # Environment/resource mismatch: neither the staging allow nor
        # the prod deny matches, so default deny applies.
        ({"tool": "db", "action": "query", "resource": "prod.users",
          "environment": "staging"}, False, "default"),
        ({"tool": "db", "action": "query", "resource": "staging.users",
          "environment": "prod"}, False, "default"),
        ({"tool": "deploy", "action": "run", "resource": "staging",
          "environment": "staging"}, True, "allow-deploy-staging"),
        ({"tool": "deploy", "action": "run", "resource": "prod",
          "environment": "prod"}, False, "deny-deploy-prod"),
        # Unknown tools are denied, never allowed.
        ({"tool": "shell", "action": "exec", "resource": ""},
         False, "default"),
        ({"tool": "browser", "action": "navigate", "resource": "https://example.com"},
         False, "default"),
        # Project dimension.
        ({"tool": "issues", "action": "read", "resource": "ticket-1",
          "project": "demo"}, True, "allow-issues-read-demo"),
        ({"tool": "issues", "action": "read", "resource": "ticket-1",
          "project": "other"}, False, "default"),
        # Matching is case-sensitive (fnmatchcase).
        ({"tool": "Files", "action": "read", "resource": "workspace/notes.txt"},
         False, "default"),
        ({"tool": "files", "action": "READ", "resource": "workspace/notes.txt"},
         False, "default"),
        # Empty resource matches no workspace rule.
        ({"tool": "files", "action": "list", "resource": ""},
         False, "default"),
        # Unconstrained fields on the db rule: any user may query staging.
        ({"tool": "db", "action": "query", "resource": "staging.users",
          "environment": "staging", "user": "dba"}, True, "allow-db-staging"),
    ]

    def test_decision_table(self):
        engine = PolicyEngine(EDGE_POLICY)
        self.assertEqual(len(self.CASES), 25)
        for kwargs, expected, fragment in self.CASES:
            with self.subTest(call=kwargs):
                decision = engine.evaluate(base_call(**kwargs))
                self.assertEqual(decision.allowed, expected, decision.reason)
                self.assertIn(fragment, decision.reason)

    def test_deny_wins_even_with_broad_allow(self):
        policy = Policy.from_dict({"rules": [
            {"id": "allow-all-db", "effect": "allow", "tool": "db"},
            {"id": "deny-db-prod", "effect": "deny", "tool": "db",
             "resource": "prod.*", "environment": "prod"},
        ]})
        engine = PolicyEngine(policy)
        self.assertFalse(engine.evaluate(base_call(
            tool="db", action="query", resource="prod.users",
            environment="prod")).allowed)
        self.assertTrue(engine.evaluate(base_call(
            tool="db", action="query", resource="staging.users",
            environment="staging")).allowed)

    def test_explain_names_the_deciding_rule(self):
        engine = PolicyEngine(EDGE_POLICY)
        decision = engine.explain(base_call(
            tool="db", action="query", resource="prod.users",
            environment="prod"))
        self.assertFalse(decision.allowed)
        self.assertIn("deny-db-prod", decision.reason)
        self.assertTrue(any("deny rule matched" in s for s in decision.steps))
        self.assertEqual(decision.matched_rules, ["deny-db-prod"])

    def test_rule_missing_field_matches_anything(self):
        # A rule with only tool+effect allows every action/resource for it.
        policy = Policy.from_dict({"rules": [
            {"id": "allow-all-files", "effect": "allow", "tool": "files"},
        ]})
        engine = PolicyEngine(policy)
        self.assertTrue(engine.evaluate(base_call(
            action="write", resource="workspace/x")).allowed)


class TestApprovalExpiry(unittest.TestCase):
    def test_approve_unknown_token_returns_false(self):
        store = ApprovalStore()
        self.assertFalse(store.approve("0" * 64))
        self.assertFalse(store.is_approved("files", "delete", {"path": "x"}))

    def test_denied_approval_cannot_be_used(self):
        store = ApprovalStore()
        token = store.request("files", "delete", {"path": "notes.txt"})
        self.assertTrue(store.deny(token))
        self.assertFalse(store.is_approved("files", "delete", {"path": "notes.txt"}))
        self.assertEqual(store.list_pending(), [])

    def test_approval_record_carries_expiry(self):
        store = ApprovalStore()
        token = store.request("files", "delete", {"path": "notes.txt"})
        record = store.pending(token)
        self.assertIn("expires_at", record)
        self.assertEqual(record["ttl_seconds"], ApprovalStore().ttl_seconds)
        self.assertEqual(store.ttl_seconds, 900)  # 15-minute default

    def test_expired_approval_must_be_refused(self):
        clock = FakeClock()
        store = ApprovalStore(ttl_seconds=60, clock=clock)
        token = store.request("files", "delete", {"path": "notes.txt"})
        self.assertTrue(store.approve(token))
        self.assertTrue(store.is_approved("files", "delete", {"path": "notes.txt"},
                                           single_use=False))
        clock.advance(61)
        self.assertFalse(store.is_approved("files", "delete", {"path": "notes.txt"}))

    def test_expired_approval_cannot_be_granted(self):
        clock = FakeClock()
        store = ApprovalStore(ttl_seconds=60, clock=clock)
        token = store.request("files", "delete", {"path": "notes.txt"})
        clock.advance(61)
        self.assertFalse(store.approve(token))
        self.assertFalse(store.is_approved("files", "delete", {"path": "notes.txt"}))

    def test_consumed_approval_cannot_be_reapproved(self):
        store = ApprovalStore()
        token = store.request("files", "delete", {"path": "notes.txt"})
        self.assertTrue(store.approve(token))
        self.assertTrue(store.is_approved("files", "delete", {"path": "notes.txt"}))
        # Consumed: re-approving the same token must fail.
        self.assertFalse(store.approve(token))
        self.assertFalse(store.is_approved("files", "delete", {"path": "notes.txt"}))

    def test_deny_after_approve_revokes(self):
        store = ApprovalStore()
        token = store.request("files", "delete", {"path": "notes.txt"})
        self.assertTrue(store.approve(token))
        self.assertTrue(store.deny(token))
        self.assertFalse(store.is_approved("files", "delete", {"path": "notes.txt"}))
        self.assertFalse(store.approve(token))

    def test_agent_cannot_approve_its_own_request(self):
        store = ApprovalStore()
        token = store.request("files", "delete", {"path": "notes.txt"}, actor="agent")
        self.assertFalse(store.approve(token, actor="agent"))
        self.assertTrue(store.approve(token, actor="human"))
        record = store.pending(token)
        self.assertEqual(record["actor"], "human")
        self.assertEqual(record["approved_by"], "human")

    def test_fresh_request_after_consumption_can_be_approved(self):
        store = ApprovalStore()
        call = ("files", "delete", {"path": "notes.txt"})
        token = store.request(*call)
        self.assertTrue(store.approve(token))
        self.assertTrue(store.is_approved(*call))
        # A new request for the same triple starts a new lifecycle.
        token2 = store.request(*call)
        self.assertTrue(store.approve(token2))
        self.assertTrue(store.is_approved(*call))


class TestBudgetEdges(unittest.TestCase):
    def test_call_budget_exactly_at_limit_blocks(self):
        manager = BudgetManager(Budget(max_calls=2))
        self.assertTrue(manager.check()[0])
        manager.record()
        self.assertTrue(manager.check()[0])  # 1/2: one call left
        manager.record()
        ok, reason = manager.check()
        self.assertFalse(ok)  # 2/2: exactly at the limit blocks
        self.assertIn("call budget", reason)

    def test_call_budget_one_over_limit_blocks(self):
        manager = BudgetManager(Budget(max_calls=1))
        manager.record()
        self.assertFalse(manager.check()[0])

    def test_call_budget_zero_means_no_calls_allowed(self):
        manager = BudgetManager(Budget(max_calls=0))
        self.assertFalse(manager.check()[0])

    def test_cost_exactly_at_ceiling_is_allowed(self):
        manager = BudgetManager(Budget(max_cost=0.05))
        # cost + prospective == ceiling is NOT "would exceed".
        self.assertTrue(manager.check(0.05)[0])
        manager.record(0.05)
        # Now at the ceiling: a free (zero-cost) check still passes,
        # but any positive cost is refused.
        self.assertTrue(manager.check(0.0)[0])
        ok, reason = manager.check(0.01)
        self.assertFalse(ok)
        self.assertIn("cost budget", reason)

    def test_cost_one_cent_over_ceiling_is_refused(self):
        manager = BudgetManager(Budget(max_cost=0.05))
        self.assertFalse(manager.check(0.06)[0])

    def test_cost_ceiling_boundary_after_partial_spend(self):
        manager = BudgetManager(Budget(max_cost=0.10))
        manager.record(0.05)
        self.assertTrue(manager.check(0.05)[0])   # reaches exactly 0.10
        self.assertFalse(manager.check(0.0500001)[0])  # one hair over
        manager.record(0.05)
        self.assertFalse(manager.check(0.0 + 1e-9)[0])

    def test_cost_block_latches(self):
        manager = BudgetManager(Budget(max_cost=0.05))
        self.assertFalse(manager.check(0.06)[0])
        self.assertFalse(manager.check(0.0)[0])
        self.assertEqual(manager.blocked_reason is not None, True)

    def test_time_budget_just_below_limit_allowed(self):
        clock = FakeClock()
        manager = BudgetManager(Budget(max_seconds=10), clock=clock)
        clock.advance(9.9)
        self.assertTrue(manager.check()[0])

    def test_time_budget_exactly_at_limit_blocks(self):
        clock = FakeClock()
        manager = BudgetManager(Budget(max_seconds=10), clock=clock)
        clock.advance(10.0)
        ok, reason = manager.check()
        self.assertFalse(ok)
        self.assertIn("time budget", reason)

    def test_time_budget_one_second_over_blocks_and_latches(self):
        clock = FakeClock()
        manager = BudgetManager(Budget(max_seconds=10), clock=clock)
        clock.advance(11)
        self.assertFalse(manager.check()[0])
        self.assertFalse(manager.check()[0])  # latched, not transient

    def test_unlimited_budget_never_blocks(self):
        manager = BudgetManager(Budget())
        for _ in range(100):
            manager.record(1.0)
        self.assertTrue(manager.check(1000.0)[0])
        self.assertEqual(manager.remaining()["calls_left"], None)
        self.assertEqual(manager.remaining()["cost_left"], None)

    def test_gateway_cost_ceiling_boundary(self):
        # db.query costs 0.02 (see tools.TOOL_COSTS). With max_cost 0.04
        # exactly two queries fit; the third would exceed the ceiling.
        fixture = _GatewayFixture()
        fixture.setUp(policy=load_demo_policy(), max_cost=0.04)
        try:
            for _ in range(2):
                result = fixture.call("db", "query",
                                      {"environment": "staging", "table": "users"})
                self.assertTrue(result["allowed"], result)
            blocked = fixture.call("db", "query",
                                   {"environment": "staging", "table": "users"})
            self.assertFalse(blocked["allowed"])
            self.assertIn("budget", blocked["reason"])
        finally:
            fixture.tearDown()

    def test_gateway_call_budget_exact_boundary(self):
        fixture = _GatewayFixture()
        fixture.setUp(policy=load_demo_policy(), max_calls=1)
        try:
            self.assertTrue(fixture.call("files", "list", {"path": "."})["allowed"])
            blocked = fixture.call("files", "list", {"path": "."})
            self.assertFalse(blocked["allowed"])
            self.assertIn("budget", blocked["reason"])
        finally:
            fixture.tearDown()


class _GatewayFixture:
    """Minimal gateway harness (mirrors tests/test_agentshield.py)."""

    def setUp(self, policy, max_calls=None, max_cost=None, max_seconds=None):
        self.tmp = tempfile.TemporaryDirectory()
        self.workspace = os.path.join(self.tmp.name, "ws")
        os.makedirs(self.workspace)
        with open(os.path.join(self.workspace, "notes.txt"), "w") as fh:
            fh.write("hello\n")
        self.policy = policy
        budgets = dict(policy.budgets)
        if max_calls is not None:
            budgets["max_calls"] = max_calls
        if max_cost is not None:
            budgets["max_cost"] = max_cost
        if max_seconds is not None:
            budgets["max_seconds"] = max_seconds
        self.broker = SecretBroker(
            scopes=policy.secret_scopes,
            source={"AGENTSHIELD_SECRET_DB_PASSWORD": "test-secret-123"})
        self.audit_path = os.path.join(self.tmp.name, "audit.jsonl")
        self.gateway = Gateway(
            policy=policy,
            tools=FakeTools(self.workspace),
            broker=self.broker,
            approvals=ApprovalStore(),
            budgets=BudgetManager(Budget(
                max_calls=budgets.get("max_calls"),
                max_seconds=budgets.get("max_seconds"),
                max_cost=budgets.get("max_cost"))),
            audit=AuditLog(self.audit_path, redact=self.broker.redact),
        )

    def tearDown(self):
        self.tmp.cleanup()

    def call(self, tool, action, args=None, environment="staging", **kw):
        return self.gateway.call(ToolCall(
            tool, action, args or {}, environment=environment, **kw))


class TestPathEscapes(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.workspace = os.path.join(self.tmp.name, "ws")
        os.makedirs(self.workspace)
        with open(os.path.join(self.workspace, "notes.txt"), "w") as fh:
            fh.write("hello\n")
        os.makedirs(os.path.join(self.workspace, "sub"))
        with open(os.path.join(self.workspace, "sub", "inner.txt"), "w") as fh:
            fh.write("inner\n")
        self.outside = os.path.join(self.tmp.name, "secret.txt")
        with open(self.outside, "w") as fh:
            fh.write("SECRET-OUTSIDE\n")
        self.tools = FakeTools(self.workspace)

    def tearDown(self):
        self.tmp.cleanup()

    def test_inside_paths_work(self):
        self.assertEqual(self.tools.files_read({"path": "notes.txt"}), "hello\n")
        self.assertEqual(self.tools.files_read({"path": "sub/inner.txt"}), "inner\n")
        self.assertEqual(self.tools.files_list({"path": "sub"}), ["inner.txt"])

    def test_dotdot_escape_read(self):
        for path in ("../secret.txt", "../../secret.txt",
                     "sub/../../secret.txt", "notes.txt/../../secret.txt"):
            with self.subTest(path=path):
                with self.assertRaises(ToolError) as ctx:
                    self.tools.files_read({"path": path})
                self.assertIn("escapes workspace", str(ctx.exception))

    def test_absolute_path_escape_read(self):
        for path in ("/etc/passwd", self.outside):
            with self.subTest(path=path):
                with self.assertRaises(ToolError) as ctx:
                    self.tools.files_read({"path": path})
                self.assertIn("escapes workspace", str(ctx.exception))

    def test_dotdot_escape_list_and_delete(self):
        for method in ("files_list", "files_delete"):
            with self.subTest(method=method):
                with self.assertRaises(ToolError):
                    getattr(self.tools, method)({"path": ".."})
        # The outside file must still exist: the escape never executed.
        with open(self.outside, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), "SECRET-OUTSIDE\n")

    def test_absolute_path_escape_list(self):
        with self.assertRaises(ToolError):
            self.tools.files_list({"path": "/etc"})

    def test_gateway_dotdot_read_leaks_nothing(self):
        fixture = _GatewayFixture()
        fixture.setUp(policy=load_demo_policy())
        try:
            result = fixture.call("files", "read", {"path": "../secret.txt"})
            self.assertIsNone(result["result"])
            self.assertNotIn("SECRET", str(result))
            # The traversal is now refused by policy *before* the tool
            # runs: the resource normalises to "secret.txt", which no
            # workspace rule matches, so the gateway denies by default
            # instead of letting the tool raise.
            self.assertFalse(result["allowed"])
            self.assertIn("default", result["reason"])
        finally:
            fixture.tearDown()

    def test_gateway_absolute_path_denied_by_policy(self):
        fixture = _GatewayFixture()
        fixture.setUp(policy=load_demo_policy())
        try:
            result = fixture.call("files", "read", {"path": "/etc/passwd"})
            self.assertFalse(result["allowed"])
            self.assertIn("default", result["reason"])
        finally:
            fixture.tearDown()

    def test_symlink_escape_is_blocked(self):
        """A symlink inside the workspace pointing outside it must not
        let the file tools read outside files. ``FakeTools._safe_path``
        resolves symlinks with ``realpath`` and re-checks containment.
        """
        link = os.path.join(self.workspace, "link.txt")
        os.symlink(self.outside, link)
        with self.assertRaises(ToolError):
            self.tools.files_read({"path": "link.txt"})

    def test_symlinked_directory_escape_is_blocked(self):
        """Same bypass via a symlinked directory (see test above)."""
        linkdir = os.path.join(self.workspace, "etclink")
        os.symlink("/etc", linkdir)
        with self.assertRaises(ToolError):
            self.tools.files_read({"path": "etclink/passwd"})


class TestYamlSubsetLimits(unittest.TestCase):
    def test_tabs_rejected(self):
        # Tab before a list item (the form in the original suite).
        with self.assertRaises(PolicyError):
            Policy.from_yaml_subset("name: t\nrules:\n\t- id: x\n")

    def test_comments_handled(self):
        policy = Policy.from_yaml_subset(
            "# a full-line comment\n"
            "name: commented # trailing comment\n"
            "rules:\n"
            "  # a comment inside the list\n"
            "  - id: x\n"
            "    effect: allow\n"
            "    tool: files # trailing comment on a value\n"
            "    resource: workspace/* # comment after a glob\n")
        self.assertEqual(policy.name, "commented")
        self.assertEqual(policy.rules[0].tool, "files")
        self.assertEqual(policy.rules[0].resource, "workspace/*")

    def test_hash_inside_quotes_is_not_a_comment(self):
        policy = Policy.from_yaml_subset(
            "name: 'a # b'\n"
            "rules:\n"
            "  - id: x\n"
            "    effect: allow\n")
        self.assertEqual(policy.name, "a # b")
        policy = Policy.from_yaml_subset(
            'name: "a: b"\n'
            "rules:\n"
            "  - id: x\n"
            "    effect: allow\n")
        self.assertEqual(policy.name, "a: b")

    def test_scalars_parsed(self):
        policy = Policy.from_yaml_subset(
            "name: t\nversion: 2\nbudgets:\n  max_calls: 3\n"
            "  max_cost: 0.5\n  max_seconds: 30\nrules:\n"
            "  - id: x\n    effect: allow\n")
        self.assertEqual(policy.version, 2)
        self.assertIsInstance(policy.version, int)
        self.assertEqual(policy.budgets,
                         {"max_calls": 3, "max_cost": 0.5, "max_seconds": 30})
        self.assertIsInstance(policy.budgets["max_cost"], float)

    def test_anchor_unsupported(self):
        with self.assertRaises(PolicyError):
            Policy.from_yaml_subset(
                "name: t\nrules: &a\n  - id: x\n    effect: allow\n")

    def test_block_scalar_unsupported(self):
        with self.assertRaises(PolicyError):
            Policy.from_yaml_subset(
                "name: t\nrules:\n  - id: x\n    effect: allow\n"
                "    tool: |\n      files\n")

    def test_flow_style_list_rejected(self):
        # 'rules: []' is flow YAML; the subset parser takes it as the
        # scalar string '[]', so the policy then fails validation with
        # a clear PolicyError instead of silently loading zero rules.
        with self.assertRaises(PolicyError):
            Policy.from_yaml_subset("name: t\nrules: []\n")

    def test_flow_style_list_in_scalar_field_rejected(self):
        # A flow list is now parsed as a list, and a rule field must be
        # a string glob pattern — so a flow list in a scalar field is a
        # clear PolicyError instead of a silent literal string that
        # matches nothing. Flow lists belong in list-valued fields
        # (e.g. secret_scopes), not in rule match fields.
        with self.assertRaises(PolicyError):
            Policy.from_yaml_subset(
                "name: t\nrules:\n  - id: x\n    effect: allow\n"
                "    tool: [files, db]\n")

    def test_nested_mapping_under_rule_rejected(self):
        with self.assertRaises(PolicyError):
            Policy.from_yaml_subset(
                "name: t\nrules:\n  - id: x\n    effect: allow\n"
                "    tool: files\n    nested:\n      a: 1\n")

    def test_empty_document_rejected(self):
        with self.assertRaises(PolicyError):
            Policy.from_yaml_subset("")
        with self.assertRaises(PolicyError):
            Policy.from_yaml_subset("# only a comment\n")

    def test_bare_string_rejected(self):
        with self.assertRaises(PolicyError):
            Policy.from_yaml_subset("just a string\n")

    def test_duplicate_rule_ids_rejected_via_yaml(self):
        with self.assertRaises(PolicyError):
            Policy.from_yaml_subset(
                "name: t\nrules:\n  - id: x\n    effect: allow\n"
                "  - id: x\n    effect: deny\n")

    def test_orphan_list_item_rejected(self):
        with self.assertRaises(PolicyError):
            Policy.from_yaml_subset(
                "name: t\nrules:\n  - id: x\n    effect: allow\n"
                "    tool: files\n  - orphan\n")


if __name__ == "__main__":
    unittest.main()
