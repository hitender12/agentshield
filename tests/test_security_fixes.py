"""Regression tests for the security fixes (QA audit, 2026-11-11).

One test class per finding. Each test first reproduces the exact
attacker-controlled input from the audit, then asserts the fixed
behaviour. Run: python3 -m unittest discover -s tests
"""

import json
import os
import random
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agentshield import (  # noqa: E402
    ApprovalStore, AuditLog, Budget, BudgetManager, Gateway, Policy,
    PolicyError, SecretBroker, ToolCall,
)
from agentshield.audit import GENESIS_HASH  # noqa: E402
from agentshield.engine import PolicyEngine  # noqa: E402
from agentshield.tools import FakeTools, ToolError  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
POLICY_DIR = os.path.join(REPO_ROOT, "policies", "examples")


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
    def setUp(self, policy=None, user="dev", project="demo"):
        self.tmp = tempfile.TemporaryDirectory()
        self.workspace = os.path.join(self.tmp.name, "ws")
        os.makedirs(self.workspace)
        with open(os.path.join(self.workspace, "notes.txt"), "w") as fh:
            fh.write("hello\n")
        self.policy = policy or load_demo_policy()
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
            user=user, project=project,
        )

    def tearDown(self):
        self.tmp.cleanup()

    def call(self, tool, action, args=None, environment="staging", **kw):
        return self.gateway.call(ToolCall(
            tool, action, args or {}, environment=environment, **kw))


class TestEnvConfusion(GatewayFixture):
    """Finding 1: policy was checked on one environment while the tool
    executed against another."""

    def test_mismatched_db_query_denied_no_prod_data(self):
        result = self.call("db", "query",
                           {"environment": "prod", "table": "users"},
                           environment="staging")
        self.assertFalse(result["allowed"])
        self.assertIn("mismatch", result["reason"])
        self.assertIsNone(result["result"])
        self.assertNotIn("10432", str(result))

    def test_mismatched_deploy_denied_even_with_approval(self):
        call = ToolCall("deploy", "run",
                        {"environment": "prod", "service": "api"},
                        environment="staging")
        token = self.gateway.request_approval(call)
        self.assertTrue(self.gateway.approvals.approve(token))
        result = self.gateway.call(call)
        self.assertFalse(result["allowed"])
        self.assertIn("mismatch", result["reason"])

    def test_matching_environments_still_work(self):
        ok = self.call("db", "query",
                       {"environment": "staging", "table": "users"})
        self.assertTrue(ok["allowed"])
        self.assertEqual(ok["result"]["rows"], 12)

    def test_policy_resource_uses_args_environment(self):
        call = ToolCall("db", "query",
                        {"environment": "prod", "table": "users"},
                        environment="prod")
        self.assertEqual(call.to_policy_call()["resource"], "prod.users")
        self.assertEqual(call.to_policy_call()["environment"], "prod")


class TestSymlinkEscape(GatewayFixture):
    """Finding 2: symlinks inside the workspace pointed outside it."""

    def test_symlink_file_blocked(self):
        outside = os.path.join(self.tmp.name, "outside.txt")
        with open(outside, "w") as fh:
            fh.write("SECRET-OUTSIDE\n")
        os.symlink(outside, os.path.join(self.workspace, "link.txt"))
        with self.assertRaises(ToolError):
            self.gateway.tools.files_read({"path": "link.txt"})

    def test_symlink_dir_blocked(self):
        os.symlink("/etc", os.path.join(self.workspace, "etclink"))
        with self.assertRaises(ToolError):
            self.gateway.tools.files_read({"path": "etclink/passwd"})

    def test_symlink_delete_blocked(self):
        outside = os.path.join(self.tmp.name, "outside.txt")
        with open(outside, "w") as fh:
            fh.write("SECRET-OUTSIDE\n")
        os.symlink(outside, os.path.join(self.workspace, "link.txt"))
        with self.assertRaises(ToolError):
            self.gateway.tools.files_delete({"path": "link.txt"})
        self.assertTrue(os.path.exists(outside))

    def test_traversal_resource_normalised_before_policy(self):
        # workspace/../secret.txt resolves to "secret.txt": no workspace
        # rule matches, so the gateway denies by default.
        call = ToolCall("files", "read", {"path": "../secret.txt"})
        self.assertEqual(call.to_policy_call()["resource"], "secret.txt")
        self.assertFalse(self.gateway.call(call)["allowed"])


class TestApprovalHardening(unittest.TestCase):
    """Finding 3: approvals were replayable, unrevocable, unexpiring,
    and grantable by the agent itself."""

    def test_replay_after_consume_fails(self):
        store = ApprovalStore()
        token = store.request("files", "delete", {"path": "x"})
        self.assertTrue(store.approve(token))
        self.assertTrue(store.is_approved("files", "delete", {"path": "x"}))
        self.assertFalse(store.approve(token))
        self.assertFalse(store.is_approved("files", "delete", {"path": "x"}))

    def test_deny_revokes_granted_approval(self):
        store = ApprovalStore()
        token = store.request("files", "delete", {"path": "x"})
        self.assertTrue(store.approve(token))
        self.assertTrue(store.deny(token))
        self.assertFalse(store.is_approved("files", "delete", {"path": "x"}))

    def test_expiry_enforced_with_fake_clock(self):
        clock = FakeClock()
        store = ApprovalStore(ttl_seconds=900, clock=clock)
        token = store.request("files", "delete", {"path": "x"})
        self.assertTrue(store.approve(token))
        clock.advance(899)
        self.assertTrue(store.has_approval("files", "delete", {"path": "x"}))
        clock.advance(2)
        self.assertFalse(store.is_approved("files", "delete", {"path": "x"}))
        self.assertFalse(store.approve(token))

    def test_human_actor_recorded(self):
        store = ApprovalStore()
        token = store.request("files", "delete", {"path": "x"}, actor="agent")
        self.assertEqual(store.pending(token)["actor"], "agent")
        self.assertTrue(store.approve(token, actor="human"))
        self.assertEqual(store.pending(token)["actor"], "human")

    def test_gateway_has_no_approve_method(self):
        # The agent's only approval surface is requesting one.
        self.assertFalse(hasattr(Gateway, "approve"))
        self.assertTrue(hasattr(Gateway, "request_approval"))


class TestRedactionGaps(GatewayFixture):
    """Finding 4: only fetched secrets were redacted; unscoped secrets
    were handed to any tool."""

    def test_unfetched_secret_is_redacted(self):
        broker = SecretBroker(
            scopes={"DB_PASSWORD": ["db"]},
            source={"AGENTSHIELD_SECRET_DB_PASSWORD": "pw-1",
                    "AGENTSHIELD_SECRET_API_KEY": "sk-live-999"})
        self.assertNotIn("sk-live-999", broker.redact("leak sk-live-999"))
        self.assertIn("[REDACTED:API_KEY]", broker.redact("leak sk-live-999"))

    def test_short_secret_is_redacted(self):
        broker = SecretBroker(
            scopes={"DB_PASSWORD": ["db"]},
            source={"AGENTSHIELD_SECRET_DB_PASSWORD": "abc"})
        self.assertNotIn("abc", broker.redact("pw is abc here"))
        self.assertIn("[REDACTED:DB_PASSWORD]", broker.redact("pw is abc here"))

    def test_unscoped_secret_denied_by_default(self):
        broker = SecretBroker(
            scopes={"DB_PASSWORD": ["db"]},
            source={"AGENTSHIELD_SECRET_API_KEY": "sk-live-999"})
        self.assertIsNone(broker.get("API_KEY", "db"))
        self.assertIsNone(broker.get("API_KEY", "files"))

    def test_scoped_secret_still_works(self):
        self.assertEqual(self.broker.get("DB_PASSWORD", "db"), "test-secret-123")
        self.assertIsNone(self.broker.get("DB_PASSWORD", "files"))

    def test_secret_in_file_path_is_redacted_in_audit(self):
        # A secret embedded in a recorded resource path must not land
        # verbatim in audit.jsonl.
        self.broker.get("DB_PASSWORD", "db")
        self.gateway.audit.record("agent", "files", "read",
                                  "workspace/test-secret-123.txt",
                                  "deny", "blocked", "no")
        raw = open(self.audit_path, encoding="utf-8").read()
        self.assertNotIn("test-secret-123", raw)


class TestBudgetChargesEveryAttempt(GatewayFixture):
    """Finding 5: denied and erroring calls looped for free."""

    def test_erroring_calls_consume_budget(self):
        self.gateway.budgets = BudgetManager(Budget(max_calls=2))
        for _ in range(2):
            result = self.call("files", "read", {"path": "missing.txt"})
            self.assertIn("error", result)  # policy allowed, tool errored
        self.assertEqual(self.gateway.budgets.calls, 2)
        blocked = self.call("files", "list", {"path": "."})
        self.assertFalse(blocked["allowed"])
        self.assertIn("budget", blocked["reason"])

    def test_policy_denied_calls_consume_budget(self):
        self.gateway.budgets = BudgetManager(Budget(max_calls=2))
        self.call("shell", "exec", {"command": "id"})  # denied by default
        self.call("shell", "exec", {"command": "id"})
        self.assertEqual(self.gateway.budgets.calls, 2)
        self.assertFalse(self.call("files", "list", {"path": "."})["allowed"])


class TestYamlFlowAndDuplicates(unittest.TestCase):
    """Finding 6: flow collections exploded into characters; duplicate
    keys silently won."""

    def test_flow_list_parses_to_list(self):
        policy = Policy.from_yaml_subset(
            "name: t\nsecret_scopes:\n  DB_PASSWORD: [db]\nrules:\n"
            "  - id: x\n    effect: allow\n")
        self.assertEqual(policy.secret_scopes, {"DB_PASSWORD": ["db"]})

    def test_flow_list_with_quotes_and_commas(self):
        policy = Policy.from_yaml_subset(
            "name: t\nsensitive_actions: [delete, 'send, now']\nrules:\n"
            "  - id: x\n    effect: allow\n")
        self.assertEqual(policy.sensitive_actions, ("delete", "send, now"))

    def test_flow_map_parses(self):
        policy = Policy.from_yaml_subset(
            "name: t\nbudgets: {max_calls: 3, max_cost: 0.5}\nrules:\n"
            "  - id: x\n    effect: allow\n")
        self.assertEqual(policy.budgets, {"max_calls": 3, "max_cost": 0.5})

    def test_duplicate_top_level_key_rejected(self):
        with self.assertRaises(PolicyError):
            Policy.from_yaml_subset(
                "name: a\nname: b\nrules:\n  - id: x\n    effect: allow\n")

    def test_duplicate_rule_field_rejected(self):
        with self.assertRaises(PolicyError):
            Policy.from_yaml_subset(
                "name: t\nrules:\n  - id: x\n    effect: allow\n"
                "    effect: deny\n")

    def test_duplicate_key_in_flow_map_rejected(self):
        with self.assertRaises(PolicyError):
            Policy.from_yaml_subset(
                "name: t\nbudgets: {max_calls: 3, max_calls: 4}\nrules:\n"
                "  - id: x\n    effect: allow\n")

    def test_unbalanced_flow_collection_rejected(self):
        with self.assertRaises(PolicyError):
            Policy.from_yaml_subset(
                "name: t\nsecret_scopes:\n  DB_PASSWORD: [db\nrules:\n"
                "  - id: x\n    effect: allow\n")


class TestAuditTamperEvidence(unittest.TestCase):
    """Finding 7: verify() crashed on corrupt lines and missed edits."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "audit.jsonl")

    def tearDown(self):
        self.tmp.cleanup()

    def test_clean_log_verifies(self):
        log = AuditLog(self.path, redact=lambda t: t)
        log.record("agent", "files", "read", "workspace/x", "allow", "ok")
        log.record("agent", "db", "query", "staging.users", "deny", "blocked")
        result = log.verify()
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["entries"], 2)

    def test_corrupt_line_reported_not_raised(self):
        log = AuditLog(self.path, redact=lambda t: t)
        log.record("agent", "files", "read", "workspace/x", "allow", "ok")
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write("{not json\n")
        log.record("agent", "files", "read", "workspace/y", "allow", "ok")
        result = log.verify()
        self.assertFalse(result["ok"])
        self.assertTrue(any("corrupt" in p for p in result["problems"]))

    def test_flipped_decision_detected(self):
        log = AuditLog(self.path, redact=lambda t: t)
        log.record("agent", "files", "delete", "workspace/x", "deny", "blocked")
        lines = open(self.path, encoding="utf-8").read().splitlines()
        entry = json.loads(lines[0])
        entry["decision"] = "allow"
        open(self.path, "w", encoding="utf-8").write(json.dumps(entry) + "\n")
        result = AuditLog(self.path).verify()
        self.assertFalse(result["ok"])
        self.assertTrue(any("hash mismatch" in p for p in result["problems"]))

    def test_deleted_middle_entry_detected(self):
        log = AuditLog(self.path, redact=lambda t: t)
        for i in range(3):
            log.record("agent", "files", "read", f"workspace/{i}", "allow", "ok")
        lines = open(self.path, encoding="utf-8").read().splitlines()
        open(self.path, "w", encoding="utf-8").write(lines[0] + "\n" + lines[2] + "\n")
        result = AuditLog(self.path).verify()
        self.assertFalse(result["ok"])
        self.assertTrue(any("chain broken" in p for p in result["problems"]))

    def test_reordered_entries_detected(self):
        log = AuditLog(self.path, redact=lambda t: t)
        for i in range(2):
            log.record("agent", "files", "read", f"workspace/{i}", "allow", "ok")
        lines = open(self.path, encoding="utf-8").read().splitlines()
        open(self.path, "w", encoding="utf-8").write(lines[1] + "\n" + lines[0] + "\n")
        self.assertFalse(AuditLog(self.path).verify()["ok"])

    def test_chain_resumes_when_appending_to_existing_log(self):
        log = AuditLog(self.path, redact=lambda t: t)
        log.record("agent", "files", "read", "workspace/x", "allow", "ok")
        log2 = AuditLog(self.path, redact=lambda t: t)
        log2.record("agent", "files", "read", "workspace/y", "allow", "ok")
        self.assertTrue(log2.verify()["ok"])


class TestPolicyTypeValidation(unittest.TestCase):
    """Finding 8: bad types silently disabled approvals or crashed."""

    def test_sensitive_actions_string_rejected(self):
        with self.assertRaises(PolicyError):
            Policy.from_dict({"rules": [{"id": "x", "effect": "allow"}],
                              "sensitive_actions": "delete"})

    def test_secret_scopes_string_value_rejected(self):
        with self.assertRaises(PolicyError):
            Policy.from_dict({"rules": [{"id": "x", "effect": "allow"}],
                              "secret_scopes": {"DB_PASSWORD": "db"}})

    def test_rule_field_non_string_rejected(self):
        with self.assertRaises(PolicyError):
            Policy.from_dict({"rules": [{"id": "x", "effect": "allow",
                                         "tool": ["files", "db"]}]})

    def test_budgets_non_number_rejected(self):
        with self.assertRaises(PolicyError):
            Policy.from_dict({"rules": [{"id": "x", "effect": "allow"}],
                              "budgets": {"max_calls": "many"}})

    def test_empty_rules_rejected(self):
        with self.assertRaises(PolicyError):
            Policy.from_dict({"rules": []})

    def test_gateway_never_crashes_on_policy_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = os.path.join(tmp, "ws")
            os.makedirs(ws)
            with open(os.path.join(ws, "notes.txt"), "w") as fh:
                fh.write("hello\n")
            policy = load_demo_policy()
            gateway = Gateway(
                policy=policy, tools=FakeTools(ws),
                broker=SecretBroker(scopes=policy.secret_scopes,
                                    source={"AGENTSHIELD_SECRET_DB_PASSWORD": "x"}),
                approvals=ApprovalStore(),
                budgets=BudgetManager(Budget()),
                audit=AuditLog(os.path.join(tmp, "a.jsonl")))
            # Sabotage evaluation: even a policy that explodes at
            # evaluation time must deny, never raise out of call().
            def boom(_call):
                raise RuntimeError("boom")
            gateway.engine.evaluate = boom
            result = gateway.call(
                ToolCall("files", "read", {"path": "notes.txt"}))
            self.assertFalse(result["allowed"])
            self.assertIn("policy evaluation error", result["reason"])


class TestExplainFullGate(GatewayFixture):
    """Finding 9: explain() ignored approval and budget."""

    def test_explain_denies_unapproved_sensitive_action(self):
        decision = self.gateway.explain(
            ToolCall("files", "delete", {"path": "notes.txt"}))
        self.assertFalse(decision.allowed)
        self.assertIn("approval", decision.reason.lower())

    def test_explain_allows_approved_sensitive_action(self):
        call = ToolCall("files", "delete", {"path": "notes.txt"})
        token = self.gateway.request_approval(call)
        self.gateway.approvals.approve(token)
        decision = self.gateway.explain(call)
        self.assertTrue(decision.allowed, decision.reason)

    def test_explain_denies_when_budget_exceeded(self):
        self.gateway.budgets = BudgetManager(Budget(max_calls=0))
        decision = self.gateway.explain(
            ToolCall("files", "read", {"path": "notes.txt"}))
        self.assertFalse(decision.allowed)
        self.assertIn("budget", decision.reason.lower())

    def test_explain_consumes_nothing(self):
        call = ToolCall("files", "delete", {"path": "notes.txt"})
        token = self.gateway.request_approval(call)
        self.gateway.approvals.approve(token)
        self.gateway.explain(call)
        # The approval is still there (explain peeks, never consumes),
        # no budget was charged, nothing was audited.
        self.assertTrue(self.gateway.approvals.has_approval(
            "files", "delete", {"path": "notes.txt"}))
        self.assertEqual(self.gateway.budgets.calls, 0)
        self.assertEqual(self.gateway.audit.read(), [])

    def test_explain_denies_environment_mismatch(self):
        decision = self.gateway.explain(ToolCall(
            "db", "query", {"environment": "prod", "table": "users"},
            environment="staging"))
        self.assertFalse(decision.allowed)
        self.assertIn("mismatch", decision.reason)


class TestConsoleScriptAndPaths(unittest.TestCase):
    """Findings 10 and 15: the installed console script failed, and CLI
    paths were relative to the caller's working directory."""

    def test_installed_console_script_demo_runs_from_any_cwd(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = dict(os.environ, PYTHONPATH=REPO_ROOT)
            result = subprocess.run(
                [sys.executable, "-m", "agentshield", "demo",
                 "--policy", os.path.join(POLICY_DIR, "demo-policy.json"),
                 "--workspace", os.path.join(tmp, "ws"),
                 "--audit", os.path.join(tmp, "audit.jsonl")],
                capture_output=True, text=True, cwd=tmp, env=env)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("human approved", result.stdout)

    def test_cli_defaults_are_repo_root_absolute(self):
        from agentshield.__main__ import (DEFAULT_AUDIT, DEFAULT_POLICY,
                                          DEFAULT_WORKSPACE)
        for path in (DEFAULT_POLICY, DEFAULT_WORKSPACE, DEFAULT_AUDIT):
            self.assertTrue(os.path.isabs(path), path)
            self.assertTrue(path.startswith(REPO_ROOT), path)

    def test_demo_does_not_delete_audit_log(self):
        from agentshield.demo import run_demo
        with tempfile.TemporaryDirectory() as tmp:
            audit = os.path.join(tmp, "audit.jsonl")
            with open(audit, "w", encoding="utf-8") as fh:
                fh.write('{"sentinel": true}\n')
            run_demo(policy_path=os.path.join(POLICY_DIR, "demo-policy.json"),
                     workspace=os.path.join(tmp, "ws"), audit_path=audit)
            raw = open(audit, encoding="utf-8").read()
            self.assertIn("sentinel", raw)  # pre-existing line survived
            self.assertGreater(len(raw.strip().splitlines()), 1)

    def test_gitignore_covers_build_artifacts(self):
        text = open(os.path.join(REPO_ROOT, ".gitignore"),
                    encoding="utf-8").read()
        self.assertIn("*.egg-info/", text)
        self.assertIn("build/", text)


class TestSessionIdentity(GatewayFixture):
    """Finding 12: per-call user/project fields are caller-controlled,
    so identity is bound to the gateway session."""

    def setUp(self):
        policy = Policy.from_dict({"name": "id-test", "rules": [
            {"id": "allow-delete-alice", "effect": "allow", "tool": "files",
             "action": "delete", "resource": "workspace/*", "user": "alice"},
            {"id": "deny-delete-bob", "effect": "deny", "tool": "files",
             "action": "delete", "resource": "workspace/*", "user": "bob"},
        ], "sensitive_actions": []})
        super().setUp(policy=policy, user="alice")

    def test_session_user_wins_over_call_user(self):
        # The call claims to be bob, but the session is alice: allowed.
        result = self.gateway.call(ToolCall(
            "files", "delete", {"path": "notes.txt"}, user="bob"))
        self.assertTrue(result["allowed"], result)

    def test_session_bob_is_denied_even_when_call_claims_alice(self):
        self.gateway.user = "bob"
        result = self.gateway.call(ToolCall(
            "files", "delete", {"path": "notes.txt"}, user="alice"))
        self.assertFalse(result["allowed"])
        self.assertIn("deny-delete-bob", result["reason"])


class TestRunIdsUnique(unittest.TestCase):
    """Finding 13: run_id was always the constant ``run-1``."""

    def test_two_logs_have_different_run_ids(self):
        with tempfile.TemporaryDirectory() as tmp:
            a = AuditLog(os.path.join(tmp, "a.jsonl"))
            b = AuditLog(os.path.join(tmp, "b.jsonl"))
            self.assertNotEqual(a.run_id, b.run_id)
            self.assertNotEqual(a.run_id, "run-1")
            self.assertTrue(a.run_id.startswith("run_"))
            self.assertEqual(len(a.run_id), 4 + 16)

    def test_explicit_run_id_still_honoured(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = AuditLog(os.path.join(tmp, "a.jsonl"), run_id="run_mine")
            self.assertEqual(log.run_id, "run_mine")


class TestFuzzAdversarialPolicies(unittest.TestCase):
    """Finding 16: random policies and calls must never crash the
    gateway, and deny-by-default must always hold."""

    SEED = 20261111

    def test_random_policies_and_calls_never_crash(self):
        rng = random.Random(self.SEED)
        tools = ["files", "db", "deploy", "shell", "browser", "issues", ""]
        actions = ["read", "list", "delete", "query", "run", "exec", "write", ""]
        resources = ["workspace/*", "workspace/**", "workspace/../x", "/etc/passwd",
                     "staging.*", "prod.*", "*", "", "workspace/deep/*"]
        envs = ["staging", "prod", "", "dev", "PROD"]
        users = ["alice", "bob", "dev", "*", ""]
        projects = ["demo", "team-alpha", "other", ""]

        for trial in range(300):
            rules = []
            for i in range(rng.randint(0, 6)):
                rule = {"id": f"r{i}", "effect": rng.choice(["allow", "deny"])}
                if rng.random() < 0.8:
                    rule["tool"] = rng.choice(tools)
                if rng.random() < 0.8:
                    rule["action"] = rng.choice(actions)
                if rng.random() < 0.8:
                    rule["resource"] = rng.choice(resources)
                if rng.random() < 0.5:
                    rule["environment"] = rng.choice(envs)
                if rng.random() < 0.3:
                    rule["user"] = rng.choice(users)
                if rng.random() < 0.3:
                    rule["project"] = rng.choice(projects)
                rules.append(rule)
            try:
                policy = Policy.from_dict({
                    "name": "fuzz",
                    "rules": rules or [{"id": "x", "effect": "deny"}],
                    "sensitive_actions": rng.sample(
                        ["delete", "run", "send", "buy"], rng.randint(0, 2)),
                    "budgets": {"max_calls": rng.choice([None, 1, 5]),
                                "max_cost": rng.choice([None, 0.01, 1.0])},
                })
            except PolicyError:
                continue  # malformed random policy: rejection is correct
            with tempfile.TemporaryDirectory() as tmp:
                ws = os.path.join(tmp, "ws")
                os.makedirs(ws)
                with open(os.path.join(ws, "notes.txt"), "w") as fh:
                    fh.write("hello\n")
                broker = SecretBroker(
                    scopes=policy.secret_scopes,
                    source={"AGENTSHIELD_SECRET_DB_PASSWORD": "s3cr3t"})
                gateway = Gateway(
                    policy=policy, tools=FakeTools(ws), broker=broker,
                    approvals=ApprovalStore(),
                    budgets=BudgetManager(Budget(
                        max_calls=policy.budgets.get("max_calls"),
                        max_cost=policy.budgets.get("max_cost"))),
                    audit=AuditLog(os.path.join(tmp, "a.jsonl"),
                                   redact=broker.redact),
                    user=rng.choice(users), project=rng.choice(projects))
                for _ in range(10):
                    tool = rng.choice(tools)
                    action = rng.choice(actions)
                    args = {}
                    if rng.random() < 0.7:
                        args["path"] = rng.choice(
                            ["notes.txt", "../secret.txt", "/etc/passwd",
                             "sub/../../x", ".", ""])
                    if rng.random() < 0.5:
                        args["table"] = rng.choice(["users", "orders", ""])
                    if rng.random() < 0.7:
                        args["environment"] = rng.choice(envs)
                    call = ToolCall(tool, action, args,
                                    environment=rng.choice(envs),
                                    user=rng.choice(users),
                                    project=rng.choice(projects))
                    # Never raises, never returns prod data unguarded.
                    result = gateway.call(call)
                    self.assertIsInstance(result, dict)
                    self.assertIn("allowed", result)
                    if result.get("result") and isinstance(result["result"], dict):
                        self.assertNotEqual(result["result"].get("rows"), 10432)
                    decision = gateway.explain(call)
                    self.assertIsInstance(decision.allowed, bool)

    def test_unknown_tool_always_denied_under_random_policies(self):
        rng = random.Random(self.SEED + 1)
        for _ in range(100):
            rules = [{"id": "a", "effect": "allow",
                      "tool": rng.choice(["files", "db", "deploy"])}]
            policy = Policy.from_dict({"rules": rules})
            engine = PolicyEngine(policy)
            call = {"tool": "shell", "action": "exec", "resource": "",
                    "environment": "staging", "user": "dev", "project": "demo"}
            self.assertFalse(engine.evaluate(call).allowed)

    def test_env_mismatch_always_denied_under_random_policies(self):
        rng = random.Random(self.SEED + 2)
        for _ in range(100):
            policy = Policy.from_dict({"rules": [
                {"id": "a", "effect": "allow", "tool": "db"},
                {"id": "b", "effect": "allow", "tool": "deploy"},
            ]})
            with tempfile.TemporaryDirectory() as tmp:
                ws = os.path.join(tmp, "ws")
                os.makedirs(ws)
                gateway = Gateway(
                    policy=policy, tools=FakeTools(ws),
                    broker=SecretBroker(scopes={}),
                    approvals=ApprovalStore(),
                    budgets=BudgetManager(Budget()),
                    audit=AuditLog(os.path.join(tmp, "a.jsonl")))
                declared = rng.choice(["staging", "prod"])
                argued = "prod" if declared == "staging" else "staging"
                tool = rng.choice(["db", "deploy"])
                result = gateway.call(ToolCall(
                    tool, "query" if tool == "db" else "run",
                    {"environment": argued, "table": "users",
                     "service": "api"}, environment=declared))
                self.assertFalse(result["allowed"])
                self.assertIn("mismatch", result["reason"])


if __name__ == "__main__":
    unittest.main()
