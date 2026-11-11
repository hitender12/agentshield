"""Tests for the example policies in policies/examples/:
strict-readonly and team-policy (JSON and YAML forms must agree,
and the gateway must enforce each policy's intent).

Run: python3 -m unittest discover -s tests
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agentshield import (  # noqa: E402
    ApprovalStore, AuditLog, Budget, BudgetManager, Gateway, Policy,
    SecretBroker, ToolCall,
)
from agentshield.tools import FakeTools  # noqa: E402

POLICY_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          "policies", "examples")


def load(name):
    return Policy.from_json_file(os.path.join(POLICY_DIR, name + ".json"))


def load_yaml(name):
    return Policy.from_yaml_subset_file(os.path.join(POLICY_DIR, name + ".yaml"))


def assert_policies_equivalent(testcase, a, b):
    testcase.assertEqual(a.name, b.name)
    testcase.assertEqual(a.version, b.version)
    testcase.assertEqual([r.id for r in a.rules], [r.id for r in b.rules])
    testcase.assertEqual(
        [(r.effect, r.tool, r.action, r.resource, r.environment, r.user, r.project)
         for r in a.rules],
        [(r.effect, r.tool, r.action, r.resource, r.environment, r.user, r.project)
         for r in b.rules])
    testcase.assertEqual(a.sensitive_actions, b.sensitive_actions)
    testcase.assertEqual(a.budgets, b.budgets)
    testcase.assertEqual(a.secret_scopes, b.secret_scopes)


class PolicyFixture:
    def setUp(self, policy_name):
        self.tmp = tempfile.TemporaryDirectory()
        self.workspace = os.path.join(self.tmp.name, "ws")
        os.makedirs(self.workspace)
        with open(os.path.join(self.workspace, "notes.txt"), "w") as fh:
            fh.write("hello\n")
        self.policy = load(policy_name)
        self.broker = SecretBroker(
            scopes=self.policy.secret_scopes,
            source={"AGENTSHIELD_SECRET_DB_PASSWORD": "test-secret-123"})
        self.gateway = Gateway(
            policy=self.policy,
            tools=FakeTools(self.workspace),
            broker=self.broker,
            approvals=ApprovalStore(),
            budgets=BudgetManager(Budget(
                max_calls=self.policy.budgets.get("max_calls"),
                max_seconds=self.policy.budgets.get("max_seconds"),
                max_cost=self.policy.budgets.get("max_cost"))),
            audit=AuditLog(os.path.join(self.tmp.name, "audit.jsonl"),
                           redact=self.broker.redact),
        )

    def tearDown(self):
        self.tmp.cleanup()

    def call(self, tool, action, args=None, environment="staging", **kw):
        return self.gateway.call(ToolCall(
            tool, action, args or {}, environment=environment, **kw))

    def approve_and_call(self, call):
        token = self.gateway.request_approval(call)
        self.assertTrue(self.gateway.approvals.approve(token))
        return self.gateway.call(call)


class TestStrictReadonlyPolicy(unittest.TestCase, PolicyFixture):
    def setUp(self):
        PolicyFixture.setUp(self, "strict-readonly")

    def tearDown(self):
        PolicyFixture.tearDown(self)

    def test_json_and_yaml_agree(self):
        assert_policies_equivalent(self, load("strict-readonly"),
                                   load_yaml("strict-readonly"))

    def test_reads_allowed(self):
        self.assertTrue(self.call("files", "list", {"path": "."})["allowed"])
        result = self.call("files", "read", {"path": "notes.txt"})
        self.assertTrue(result["allowed"])
        self.assertEqual(result["result"], "hello\n")
        self.assertTrue(self.call("db", "query",
                                  {"environment": "staging", "table": "users"})["allowed"])

    def test_no_write_or_delete_even_with_approval(self):
        for tool, action, args in (
                ("files", "write", {"path": "notes.txt"}),
                ("files", "delete", {"path": "notes.txt"})):
            call = ToolCall(tool, action, args)
            self.approve_and_call(call)  # approval granted, policy still denies
            result = self.gateway.call(call)
            with self.subTest(call=(tool, action)):
                self.assertFalse(result["allowed"])
                self.assertTrue(os.path.exists(
                    os.path.join(self.workspace, "notes.txt")))

    def test_no_deploy_or_shell_even_with_approval(self):
        for tool, action, args, env in (
                ("deploy", "run", {"environment": "staging", "service": "api"}, "staging"),
                ("shell", "exec", {"command": "id"}, "staging")):
            call = ToolCall(tool, action, args, environment=env)
            self.approve_and_call(call)
            with self.subTest(call=(tool, action)):
                self.assertFalse(self.gateway.call(call)["allowed"])

    def test_prod_db_denied(self):
        result = self.call("db", "query",
                           {"environment": "prod", "table": "users"},
                           environment="prod")
        self.assertFalse(result["allowed"])
        self.assertIn("deny-db-prod", result["reason"])

    def test_explicit_deny_rules_present(self):
        ids = {r.id for r in self.policy.rules}
        for expected in ("deny-files-write", "deny-files-delete",
                         "deny-deploy-any", "deny-shell-exec", "deny-db-prod"):
            self.assertIn(expected, ids)


class TestTeamPolicy(unittest.TestCase, PolicyFixture):
    def setUp(self):
        PolicyFixture.setUp(self, "team-policy")

    def tearDown(self):
        PolicyFixture.tearDown(self)

    def test_json_and_yaml_agree(self):
        assert_policies_equivalent(self, load("team-policy"),
                                   load_yaml("team-policy"))

    def test_staging_db_allowed_prod_db_denied(self):
        self.assertTrue(self.call("db", "query",
                                  {"environment": "staging", "table": "users"})["allowed"])
        denied = self.call("db", "query",
                           {"environment": "prod", "table": "users"},
                           environment="prod")
        self.assertFalse(denied["allowed"])
        self.assertIn("deny-db-prod", denied["reason"])

    def test_staging_deploy_needs_approval(self):
        staging = ToolCall("deploy", "run",
                           {"environment": "staging", "service": "api"},
                           environment="staging")
        refused = self.gateway.call(staging)
        self.assertFalse(refused["allowed"])
        self.assertIn("approval required", refused["reason"])
        approved = self.approve_and_call(staging)
        self.assertTrue(approved["allowed"], approved)
        self.assertEqual(approved["result"], "deployed api to staging")

    def test_prod_deploy_denied_even_with_approval(self):
        prod = ToolCall("deploy", "run",
                        {"environment": "prod", "service": "api"},
                        environment="prod")
        self.approve_and_call(prod)  # approval granted, policy still denies
        result = self.gateway.call(prod)
        self.assertFalse(result["allowed"])
        self.assertIn("deny-deploy-prod", result["reason"])

    def test_delete_staging_needs_approval_prod_denied(self):
        staging = ToolCall("files", "delete", {"path": "notes.txt"},
                           environment="staging")
        self.assertFalse(self.gateway.call(staging)["allowed"])
        self.assertTrue(self.approve_and_call(staging)["allowed"])
        self.assertFalse(os.path.exists(os.path.join(self.workspace, "notes.txt")))
        # Recreate the file, then prod delete must be denied outright.
        with open(os.path.join(self.workspace, "notes.txt"), "w") as fh:
            fh.write("hello\n")
        prod = ToolCall("files", "delete", {"path": "notes.txt"},
                        environment="prod")
        self.approve_and_call(prod)
        result = self.gateway.call(prod)
        self.assertFalse(result["allowed"])
        self.assertIn("deny-files-delete-prod", result["reason"])
        self.assertTrue(os.path.exists(os.path.join(self.workspace, "notes.txt")))

    def test_files_read_allowed_in_both_environments(self):
        for env in ("staging", "prod"):
            result = self.call("files", "read", {"path": "notes.txt"},
                               environment=env)
            self.assertTrue(result["allowed"], env)
            self.assertEqual(result["result"], "hello\n")

    def test_issues_scoped_to_team_alpha_project(self):
        decision = self.gateway.explain(ToolCall(
            "issues", "read", {"id": "1"}, project="team-alpha"))
        self.assertTrue(decision.allowed)
        self.assertIn("allow-issues-read-team-alpha", decision.reason)
        decision = self.gateway.explain(ToolCall(
            "issues", "read", {"id": "1"}, project="other-team"))
        self.assertFalse(decision.allowed)


if __name__ == "__main__":
    unittest.main()
