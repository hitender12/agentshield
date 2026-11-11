"""Tests for AgentShield: policy engine, gateway, approvals, budgets,
secrets, and audit redaction. Run: python -m unittest discover -s tests"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agentshield import (  # noqa: E402
    ApprovalStore, AuditLog, Budget, BudgetManager, Gateway, Policy,
    PolicyError, SecretBroker, ToolCall,
)
from agentshield.approval import approval_token  # noqa: E402
from agentshield.engine import PolicyEngine  # noqa: E402
from agentshield.tools import FakeTools  # noqa: E402

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


class GatewayFixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.workspace = os.path.join(self.tmp.name, "ws")
        os.makedirs(self.workspace)
        with open(os.path.join(self.workspace, "notes.txt"), "w") as fh:
            fh.write("hello\n")
        self.policy = load_demo_policy()
        self.broker = SecretBroker(
            scopes=self.policy.secret_scopes,
            source={"AGENTSHIELD_SECRET_DB_PASSWORD": "test-secret-123"})
        self.audit_path = os.path.join(self.tmp.name, "audit.jsonl")
        self.gateway = Gateway(
            policy=self.policy,
            tools=FakeTools(self.workspace),
            broker=self.broker,
            approvals=ApprovalStore(),
            budgets=BudgetManager(Budget(
                max_calls=self.policy.budgets.get("max_calls"),
                max_seconds=self.policy.budgets.get("max_seconds"),
                max_cost=self.policy.budgets.get("max_cost"))),
            audit=AuditLog(self.audit_path, redact=self.broker.redact),
        )

    def tearDown(self):
        self.tmp.cleanup()

    def call(self, tool, action, args=None, environment="staging"):
        return self.gateway.call(
            ToolCall(tool, action, args or {}, environment=environment))


class TestPolicyLoading(unittest.TestCase):
    def test_json_loads(self):
        policy = load_demo_policy()
        self.assertEqual(policy.name, "demo")
        self.assertEqual(len(policy.rules), 7)

    def test_yaml_subset_matches_json(self):
        from_json = load_demo_policy()
        from_yaml = Policy.from_yaml_subset_file(
            os.path.join(POLICY_DIR, "demo-policy.yaml"))
        self.assertEqual([r.id for r in from_yaml.rules],
                         [r.id for r in from_json.rules])
        self.assertEqual(from_yaml.sensitive_actions, from_json.sensitive_actions)
        self.assertEqual(from_yaml.budgets, from_json.budgets)
        self.assertEqual(from_yaml.secret_scopes, from_json.secret_scopes)

    def test_yaml_subset_scalars_and_lists(self):
        policy = Policy.from_yaml_subset(
            "name: tiny\nversion: 2\nsensitive_actions:\n  - delete\n"
            "budgets:\n  max_calls: 3\nrules:\n"
            "  - id: a1\n    effect: allow\n    tool: files\n")
        self.assertEqual(policy.name, "tiny")
        self.assertEqual(policy.version, 2)
        self.assertEqual(policy.sensitive_actions, ("delete",))
        self.assertEqual(policy.budgets, {"max_calls": 3})
        self.assertEqual(policy.rules[0].tool, "files")

    def test_bad_effect_rejected(self):
        with self.assertRaises(PolicyError):
            Policy.from_dict({"rules": [{"id": "x", "effect": "maybe"}]})

    def test_duplicate_rule_ids_rejected(self):
        with self.assertRaises(PolicyError):
            Policy.from_dict({"rules": [
                {"id": "x", "effect": "allow"},
                {"id": "x", "effect": "deny"}]})

    def test_unknown_rule_field_rejected(self):
        with self.assertRaises(PolicyError):
            Policy.from_dict({"rules": [
                {"id": "x", "effect": "allow", "surprise": True}]})

    def test_yaml_tabs_rejected(self):
        with self.assertRaises(PolicyError):
            Policy.from_yaml_subset("name: t\nrules:\n\t- id: x\n")


class TestEngineDecisionTable(GatewayFixture):
    def test_decision_table(self):
        engine = PolicyEngine(self.policy)
        cases = [
            # (call dict, expected allowed, reason substring)
            ({"tool": "files", "action": "list", "resource": "workspace/.",
              "environment": "staging"}, True, "allow-files-in-workspace"),
            ({"tool": "files", "action": "read", "resource": "workspace/notes.txt",
              "environment": "staging"}, True, "allow-read-workspace"),
            ({"tool": "files", "action": "read", "resource": "/etc/passwd",
              "environment": "staging"}, False, "default"),
            ({"tool": "db", "action": "query", "resource": "staging.users",
              "environment": "staging"}, True, "allow-db-staging"),
            ({"tool": "db", "action": "query", "resource": "prod.users",
              "environment": "prod"}, False, "deny-db-prod"),
            ({"tool": "deploy", "action": "run", "resource": "staging",
              "environment": "staging"}, True, "allow-deploy-staging"),
            ({"tool": "deploy", "action": "run", "resource": "prod",
              "environment": "prod"}, False, "deny-deploy-prod"),
            ({"tool": "shell", "action": "exec", "resource": "",
              "environment": "staging"}, False, "default"),
            ({"tool": "files", "action": "write", "resource": "workspace/x",
              "environment": "staging"}, False, "default"),
        ]
        for call, expected, fragment in cases:
            with self.subTest(call=call):
                decision = engine.evaluate(call)
                self.assertEqual(decision.allowed, expected, decision.reason)
                self.assertIn(fragment, decision.reason)

    def test_deny_wins_over_allow(self):
        policy = Policy.from_dict({"rules": [
            {"id": "a", "effect": "allow", "tool": "db"},
            {"id": "d", "effect": "deny", "tool": "db", "environment": "prod"},
        ]})
        engine = PolicyEngine(policy)
        self.assertFalse(engine.evaluate(
            {"tool": "db", "action": "query", "resource": "prod.users",
             "environment": "prod"}).allowed)
        self.assertTrue(engine.evaluate(
            {"tool": "db", "action": "query", "resource": "staging.users",
             "environment": "staging"}).allowed)


class TestGateway(GatewayFixture):
    def test_unknown_tool_denied_by_default(self):
        result = self.call("shell", "exec", {"command": "id"})
        self.assertFalse(result["allowed"])
        self.assertIn("default", result["reason"])

    def test_unconfigured_action_denied(self):
        result = self.call("files", "write", {"path": "notes.txt"})
        self.assertFalse(result["allowed"])

    def test_staging_allowed_prod_denied(self):
        ok = self.call("db", "query", {"environment": "staging", "table": "users"})
        self.assertTrue(ok["allowed"])
        self.assertEqual(ok["result"]["rows"], 12)
        denied = self.call("db", "query", {"environment": "prod", "table": "users"},
                           environment="prod")
        self.assertFalse(denied["allowed"])
        self.assertIn("deny-db-prod", denied["reason"])

    def test_forbidden_path_denied(self):
        result = self.call("files", "read", {"path": "/etc/passwd"})
        self.assertFalse(result["allowed"])

    def test_delete_without_approval_refused(self):
        result = self.call("files", "delete", {"path": "notes.txt"})
        self.assertFalse(result["allowed"])
        self.assertIn("approval required", result["reason"])
        self.assertTrue(os.path.exists(os.path.join(self.workspace, "notes.txt")))

    def test_delete_with_approval_succeeds(self):
        call = ToolCall("files", "delete", {"path": "notes.txt"})
        token = self.gateway.request_approval(call)
        self.assertTrue(self.gateway.approvals.approve(token))
        result = self.gateway.call(call)
        self.assertTrue(result["allowed"])
        self.assertFalse(os.path.exists(os.path.join(self.workspace, "notes.txt")))

    def test_approval_invalidated_when_arguments_change(self):
        call = ToolCall("files", "delete", {"path": "notes.txt"})
        token = self.gateway.request_approval(call)
        self.gateway.approvals.approve(token)
        changed = ToolCall("files", "delete", {"path": "other.txt"})
        result = self.gateway.call(changed)
        self.assertFalse(result["allowed"])
        self.assertIn("approval required", result["reason"])
        # The original approval still covers the original args.
        self.assertTrue(self.gateway.call(call)["allowed"])

    def test_approval_is_single_use(self):
        call = ToolCall("files", "delete", {"path": "notes.txt"})
        token = self.gateway.request_approval(call)
        self.gateway.approvals.approve(token)
        self.assertTrue(self.gateway.call(call)["allowed"])
        with open(os.path.join(self.workspace, "notes.txt"), "w") as fh:
            fh.write("hello\n")
        result = self.gateway.call(call)
        self.assertFalse(result["allowed"])

    def test_approval_token_is_deterministic(self):
        self.assertEqual(
            approval_token("files", "delete", {"path": "a.txt"}),
            approval_token("files", "delete", {"path": "a.txt"}))
        self.assertNotEqual(
            approval_token("files", "delete", {"path": "a.txt"}),
            approval_token("files", "delete", {"path": "b.txt"}))

    def test_deploy_staging_needs_approval_prod_denied(self):
        staging = ToolCall("deploy", "run",
                           {"environment": "staging", "service": "api"},
                           environment="staging")
        self.assertFalse(self.gateway.call(staging)["allowed"])
        token = self.gateway.request_approval(staging)
        self.gateway.approvals.approve(token)
        self.assertTrue(self.gateway.call(staging)["allowed"])
        prod = ToolCall("deploy", "run",
                        {"environment": "prod", "service": "api"},
                        environment="prod")
        self.assertFalse(self.gateway.call(prod)["allowed"])

    def test_explain_mode_gives_correct_reason(self):
        prod = ToolCall("db", "query", {"environment": "prod", "table": "users"},
                        environment="prod")
        decision = self.gateway.explain(prod)
        self.assertFalse(decision.allowed)
        self.assertIn("deny-db-prod", decision.reason)
        staging = ToolCall("db", "query",
                           {"environment": "staging", "table": "users"},
                           environment="staging")
        decision = self.gateway.explain(staging)
        self.assertTrue(decision.allowed)
        self.assertIn("allow-db-staging", decision.reason)
        # Explain never executes: no audit entry, no budget consumed.
        self.assertEqual(self.gateway.audit.read(), [])
        self.assertEqual(self.gateway.budgets.calls, 0)


class TestBudgets(unittest.TestCase):
    def test_call_budget_blocks(self):
        manager = BudgetManager(Budget(max_calls=2))
        self.assertTrue(manager.check()[0])
        manager.record()
        self.assertTrue(manager.check()[0])
        manager.record()
        ok, reason = manager.check()
        self.assertFalse(ok)
        self.assertIn("call budget", reason)

    def test_cost_budget_blocks(self):
        manager = BudgetManager(Budget(max_cost=0.05))
        self.assertTrue(manager.check(0.02)[0])
        manager.record(0.02)
        self.assertTrue(manager.check(0.01)[0])
        self.assertFalse(manager.check(0.05)[0])
        # A block latches: once exceeded, later calls stay blocked.
        self.assertFalse(manager.check(0.01)[0])

    def test_time_budget_with_fake_clock(self):
        clock = FakeClock()
        manager = BudgetManager(Budget(max_seconds=10), clock=clock)
        self.assertTrue(manager.check()[0])
        clock.advance(11)
        ok, reason = manager.check()
        self.assertFalse(ok)
        self.assertIn("time budget", reason)

    def test_gateway_enforces_call_budget(self):
        fixture = TestGateway("test_unknown_tool_denied_by_default")
        fixture.setUp()
        try:
            fixture.gateway.budgets = BudgetManager(Budget(max_calls=1))
            self.assertTrue(fixture.call("files", "list", {"path": "."})["allowed"])
            blocked = fixture.call("files", "list", {"path": "."})
            self.assertFalse(blocked["allowed"])
            self.assertIn("budget", blocked["reason"])
        finally:
            fixture.tearDown()


class TestSecretsAndAudit(GatewayFixture):
    def test_broker_out_of_scope_returns_none(self):
        self.assertIsNone(self.broker.get("DB_PASSWORD", "files"))

    def test_broker_in_scope_returns_value(self):
        self.assertEqual(self.broker.get("DB_PASSWORD", "db"), "test-secret-123")

    def test_broker_missing_secret_returns_none(self):
        self.assertIsNone(self.broker.get("NO_SUCH_SECRET", "db"))

    def test_audit_log_contains_no_secrets(self):
        # Force the secret into a recorded detail string, as a careless
        # tool might, and check the audit writer redacts it.
        self.broker.get("DB_PASSWORD", "db")
        self.gateway.audit.record("agent", "db", "query", "staging.users",
                                  "allow", "ok",
                                  "connected with test-secret-123")
        self.gateway.audit.record("agent", "db", "query", "staging.users",
                                  "allow", "ok", "clean detail")
        raw = open(self.audit_path, encoding="utf-8").read()
        self.assertNotIn("test-secret-123", raw)
        self.assertIn("[REDACTED:DB_PASSWORD]", raw)
        self.assertEqual(self.gateway.audit.verify()["ok"], True)

    def test_audit_records_denials_too(self):
        self.call("shell", "exec", {"command": "id"})
        entries = self.gateway.audit.read()
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["decision"], "deny")
        self.assertEqual(entries[0]["tool"], "shell")
        for field in ("ts", "actor", "tool", "action", "resource",
                      "decision", "outcome"):
            self.assertIn(field, entries[0])


if __name__ == "__main__":
    unittest.main()
