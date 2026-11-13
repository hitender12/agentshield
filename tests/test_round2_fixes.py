"""Regression tests for the round-2 fixes (re-audit, 2026-11-11).

One test class per finding. Each test first reproduces the exact
attacker-controlled input from the re-audit, then asserts the fixed
behaviour. Run: python3 -m unittest discover -s tests
"""

import hashlib
import json
import os
import random
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agentshield import (  # noqa: E402
    ApprovalStore, AuditLog, Budget, BudgetManager, Gateway, Policy,
    PolicyError, SecretBroker, ToolCall,
)
from agentshield.approval import approval_token  # noqa: E402
from agentshield.policy import _parse_yaml_subset  # noqa: E402
from agentshield.tools import FakeTools, ToolError  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
POLICY_DIR = os.path.join(REPO_ROOT, "policies", "examples")


def load_demo_policy():
    return Policy.from_json_file(os.path.join(POLICY_DIR, "demo-policy.json"))


class GatewayFixture(unittest.TestCase):
    def setUp(self, budgets=None):
        self.tmp = tempfile.TemporaryDirectory()
        self.workspace = os.path.join(self.tmp.name, "ws")
        os.makedirs(self.workspace)
        with open(os.path.join(self.workspace, "notes.txt"), "w") as fh:
            fh.write("hello\n")
        with open(os.path.join(self.workspace, "binary.bin"), "wb") as fh:
            fh.write(b"\x00\x01\xff\xfe binary \x80\x81")
        self.policy = load_demo_policy()
        self.broker = SecretBroker(
            scopes=self.policy.secret_scopes,
            source={"AGENTSHIELD_SECRET_DB_PASSWORD": "test-secret-123"})
        self.audit_path = os.path.join(self.tmp.name, "audit.jsonl")
        self.gateway = Gateway(
            policy=self.policy, tools=FakeTools(self.workspace),
            broker=self.broker, approvals=ApprovalStore(),
            budgets=BudgetManager(Budget(**(budgets or {}))),
            audit=AuditLog(self.audit_path, redact=self.broker.redact))

    def tearDown(self):
        self.tmp.cleanup()


class TestMalformedInputNeverRaises(GatewayFixture):
    """Finding 1: gateway.call() raised on non-string paths, args=None,
    unhashable db args, binary files, and unserializable actors."""

    def test_non_string_paths_denied_not_raised(self):
        for bad_path in (123, None, ["x"], {"a": 1}, ("x",), 3.14, True):
            with self.subTest(path=bad_path):
                result = self.gateway.call(
                    ToolCall("files", "read", {"path": bad_path}))
                self.assertIsInstance(result, dict)
                self.assertFalse(result["allowed"], result)

    def test_args_not_a_mapping_denied_not_raised(self):
        for bad_args in (None, "x", ["read"], 42):
            with self.subTest(args=bad_args):
                result = self.gateway.call(ToolCall("files", "list", bad_args))
                self.assertIsInstance(result, dict)
                self.assertFalse(result["allowed"])
                self.assertIn("malformed", result["reason"])

    def test_unhashable_db_args_denied_not_raised(self):
        # A non-string environment falls back to the declared one for
        # policy purposes, so the call may be policy-allowed — but the
        # tool then refuses the malformed argument and returns no data.
        for args in ({"environment": ["prod"], "table": "users"},
                     {"environment": {"e": "prod"}, "table": "users"}):
            with self.subTest(args=args):
                result = self.gateway.call(
                    ToolCall("db", "query", args, environment="staging"))
                self.assertIsInstance(result, dict)
                self.assertIsNone(result["result"])
                self.assertNotIn("10432", str(result))
        # A non-string table makes the policy resource empty, so the
        # call denies by default.
        result = self.gateway.call(ToolCall(
            "db", "query", {"environment": "staging", "table": {"t": 1}},
            environment="staging"))
        self.assertFalse(result["allowed"])

    def test_binary_file_is_tool_error_not_crash(self):
        result = self.gateway.call(
            ToolCall("files", "read", {"path": "binary.bin"}))
        self.assertTrue(result["allowed"])  # policy allowed it
        self.assertIn("error", result)  # the tool refused it cleanly
        self.assertIn("UTF-8", result["error"])

    def test_unserializable_actor_does_not_crash_audit(self):
        result = self.gateway.call(
            ToolCall("files", "list", {"path": "."}, actor=object()))
        self.assertIsInstance(result, dict)
        self.assertTrue(result["allowed"])
        raw = open(self.audit_path, encoding="utf-8").read()
        self.assertIn("files", raw)  # the entry was written

    def test_explain_never_raises_on_malformed_input(self):
        for call in (ToolCall("files", "read", {"path": 123}),
                     ToolCall("files", "list", None),
                     ToolCall("db", "query",
                              {"environment": ["prod"], "table": "users"},
                              environment="staging"),
                     ToolCall("files", "list", {"path": "."}, actor=object())):
            decision = self.gateway.explain(call)
            self.assertIsInstance(decision.allowed, bool)

    def test_dispatch_validates_types(self):
        tools = self.gateway.tools
        with self.assertRaises(ToolError):
            tools.dispatch("files", "read", "not-a-dict")
        with self.assertRaises(ToolError):
            tools.dispatch(["files"], "read", {})
        with self.assertRaises(ToolError):
            tools.db_query({"environment": ["staging"], "table": "users"})
        with self.assertRaises(ToolError):
            tools.files_read({"path": 123})

    def test_to_policy_call_never_raises(self):
        for call in (ToolCall("files", "read", {"path": 123}),
                     ToolCall("db", "query",
                              {"environment": ["prod"], "table": {"t": 1}},
                              environment="staging"),
                     ToolCall("deploy", "run", {"environment": ["prod"]},
                              environment=123),
                     ToolCall("files", "list", None)):
            pcall = call.to_policy_call()
            self.assertIsInstance(pcall["resource"], str)
            self.assertIsInstance(pcall["environment"], str)


class TestAuditRedactsAllFields(GatewayFixture):
    """Finding 2: audit.record() redacted only resource and detail;
    a secret in actor/tool/action landed verbatim."""

    def test_secret_in_actor_is_redacted(self):
        secret = "test-secret-123"
        self.gateway.call(ToolCall("files", "list", {"path": "."}, actor=secret))
        raw = open(self.audit_path, encoding="utf-8").read()
        self.assertNotIn(secret, raw)
        self.assertIn("[REDACTED:DB_PASSWORD]", raw)

    def test_secret_in_tool_and_action_is_redacted(self):
        secret = "test-secret-123"
        self.gateway.call(ToolCall(secret, "list", {"path": "."}))
        self.gateway.call(ToolCall("files", secret, {"path": "."}))
        raw = open(self.audit_path, encoding="utf-8").read()
        self.assertNotIn(secret, raw)


class TestVerifyTamperMasking(unittest.TestCase):
    """Finding 3: flipping the last entry + corrupting the penultimate
    line made verify() report only the corrupt line."""

    def _log_with_entries(self, path, count=3):
        log = AuditLog(path, redact=lambda t: t)
        for i in range(count):
            log.record("agent", "files", "read", f"workspace/{i}",
                       "deny" if i == count - 1 else "allow", "blocked")
        return log

    def test_flip_last_plus_corrupt_penultimate_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "audit.jsonl")
            log = self._log_with_entries(path)
            lines = open(path, encoding="utf-8").read().splitlines()
            entries = [json.loads(line) for line in lines]
            last = entries[-1]
            last["decision"] = "allow"
            last.pop("hash")
            canon = {k: v for k, v in last.items()}
            last["hash"] = hashlib.sha256(
                json.dumps(canon, sort_keys=True,
                           separators=(",", ":")).encode()).hexdigest()
            lines[-2] = "{corrupt"
            lines[-1] = json.dumps(last, sort_keys=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("\n".join(lines) + "\n")
            result = log.verify()
            self.assertFalse(result["ok"])
            self.assertTrue(any("line 3" in p for p in result["problems"]),
                            result["problems"])

    def test_corrupt_first_line_still_chains_next_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "audit.jsonl")
            log = self._log_with_entries(path)
            lines = open(path, encoding="utf-8").read().splitlines()
            lines[0] = "{corrupt"
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("\n".join(lines) + "\n")
            result = log.verify()
            self.assertFalse(result["ok"])
            # Entry 2 chains from genesis, not from the (corrupt) entry 1.
            self.assertTrue(any("line 2" in p and "chain broken" in p
                                for p in result["problems"]),
                            result["problems"])

    def test_tail_rewrite_with_recomputed_hashes_is_documented_limit(self):
        # Flipping the LAST entry and recomputing its hash is
        # self-consistent: no file-local check can detect it. verify()
        # is honest about that limit (see THREAT_MODEL.md) — this test
        # pins the behaviour so a future claim cannot oversell it.
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "audit.jsonl")
            log = self._log_with_entries(path)
            lines = open(path, encoding="utf-8").read().splitlines()
            last = json.loads(lines[-1])
            last["decision"] = "allow"
            last.pop("hash")
            canon = {k: v for k, v in last.items()}
            last["hash"] = hashlib.sha256(
                json.dumps(canon, sort_keys=True,
                           separators=(",", ":")).encode()).hexdigest()
            lines[-1] = json.dumps(last, sort_keys=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("\n".join(lines) + "\n")
            # Undetectable from the file alone — but the documented
            # limit says exactly that, so this is expected, not a bug.
            self.assertTrue(log.verify()["ok"])


class TestYamlAnchorsAliasesAndDepth(unittest.TestCase):
    """Findings 4 and 5: anchors/aliases silently misparsed; deep
    nesting raised RecursionError instead of PolicyError."""

    def test_anchor_rejected(self):
        with self.assertRaises(PolicyError):
            Policy.from_yaml_subset(
                "name: &a x\nrules:\n  - id: r1\n    effect: allow\n")

    def test_alias_rejected(self):
        with self.assertRaises(PolicyError):
            Policy.from_yaml_subset(
                "name: t\nrules:\n  - id: r1\n    effect: allow\n    tool: *x\n")

    def test_anchor_as_key_rejected(self):
        with self.assertRaises(PolicyError):
            Policy.from_yaml_subset(
                "&a: x\nrules:\n  - id: r1\n    effect: allow\n")

    def test_tag_rejected(self):
        with self.assertRaises(PolicyError):
            Policy.from_yaml_subset(
                "name: !tag t\nrules:\n  - id: r1\n    effect: allow\n")

    def test_block_scalar_rejected(self):
        for indicator in ("|", ">", "|-", ">-"):
            with self.subTest(indicator=indicator):
                with self.assertRaises(PolicyError):
                    Policy.from_yaml_subset(
                        f"name: {indicator}\n  folded\n"
                        "rules:\n  - id: r1\n    effect: allow\n")

    def test_document_marker_rejected(self):
        with self.assertRaises(PolicyError):
            Policy.from_yaml_subset(
                "name: ---\nrules:\n  - id: r1\n    effect: allow\n")

    def test_quoted_star_still_a_legal_glob(self):
        policy = Policy.from_yaml_subset(
            "name: t\nrules:\n  - id: r1\n    effect: allow\n"
            "    tool: files\n    resource: '*'\n")
        self.assertEqual(policy.rules[0].resource, "*")

    def test_deep_nesting_rejected_as_policy_error(self):
        text = "".join("  " * i + f"k{i}:\n" for i in range(2000))
        with self.assertRaises(PolicyError):
            Policy.from_yaml_subset(text)

    def test_deep_flow_nesting_rejected(self):
        text = "name: t\nrules:\n  - id: r1\n    effect: allow\n    tool: " + "[" * 100 + "]" * 100 + "\n"
        with self.assertRaises(PolicyError):
            Policy.from_yaml_subset(text)

    def test_shallow_nesting_still_parses(self):
        parsed = _parse_yaml_subset(
            "a:\n  b:\n    c:\n      d: 1\n")
        self.assertEqual(parsed, {"a": {"b": {"c": {"d": 1}}}})


class TestApprovalTokenTypes(unittest.TestCase):
    """Finding 6: json.dumps(default=str) made list and tuple args the
    identical token."""

    def test_list_and_tuple_are_distinct_tokens(self):
        self.assertNotEqual(
            approval_token("files", "delete", {"x": [1, 2]}),
            approval_token("files", "delete", {"x": (1, 2)}))

    def test_nested_list_vs_tuple_distinct(self):
        self.assertNotEqual(
            approval_token("files", "delete", {"x": [[1], [2]]}),
            approval_token("files", "delete", {"x": [(1,), (2,)]}))

    def test_int_and_string_keys_distinct(self):
        self.assertNotEqual(
            approval_token("files", "delete", {1: "a"}),
            approval_token("files", "delete", {"1": "a"}))

    def test_same_args_same_token(self):
        self.assertEqual(
            approval_token("files", "delete", {"x": [1, 2]}),
            approval_token("files", "delete", {"x": [1, 2]}))

    def test_non_json_arg_values_raise(self):
        for bad in ({"x": {1, 2}}, {"x": b"bytes"}, {"x": object()}):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    approval_token("files", "delete", bad)

    def test_non_string_tool_or_action_raise(self):
        with self.assertRaises(TypeError):
            approval_token(123, "delete", {})
        with self.assertRaises(TypeError):
            approval_token("files", None, {})

    def test_gateway_denies_non_json_args_instead_of_crashing(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = os.path.join(tmp, "ws")
            os.makedirs(ws)
            with open(os.path.join(ws, "notes.txt"), "w") as fh:
                fh.write("hello\n")
            gateway = Gateway(
                policy=load_demo_policy(), tools=FakeTools(ws),
                broker=SecretBroker(scopes={}),
                approvals=ApprovalStore(), budgets=BudgetManager(Budget()),
                audit=AuditLog(os.path.join(tmp, "a.jsonl")))
            # Non-string path: the policy view has no resource, so the
            # call denies by default without ever reaching approval.
            result = gateway.call(ToolCall(
                "files", "delete", {"path": {"not": "json-set"}}))
            self.assertIsInstance(result, dict)
            self.assertFalse(result["allowed"])
            # A set-valued *extra* arg on an otherwise allowed sensitive
            # call: policy allows, but the approval token cannot be
            # computed -> denied, not raised.
            result = gateway.call(ToolCall(
                "files", "delete", {"path": "notes.txt", "extra": {1, 2}}))
            self.assertFalse(result["allowed"])
            self.assertIn("approval", result["reason"])


class TestApprovalStoreTtl(unittest.TestCase):
    """Finding 7: ApprovalStore(ttl_seconds=None) crashed on first use."""

    def test_none_ttl_rejected_at_construction(self):
        with self.assertRaises(ValueError):
            ApprovalStore(ttl_seconds=None)

    def test_non_positive_or_non_numeric_ttl_rejected(self):
        for bad in (0, -5, "900", True):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    ApprovalStore(ttl_seconds=bad)


class TestDbCredentialSemantics(GatewayFixture):
    """Finding 8: the DB credential does not gate data access — rows
    are returned with authenticated False when no credential is
    configured. This pins the documented behaviour (see THREAT_MODEL.md):
    policy is the only gate; secret scoping only controls handoff."""

    def test_rows_returned_without_credential_authenticated_false(self):
        gateway = Gateway(
            policy=self.policy, tools=FakeTools(self.workspace),
            broker=SecretBroker(scopes=self.policy.secret_scopes, source={}),
            approvals=ApprovalStore(), budgets=BudgetManager(Budget()),
            audit=AuditLog(os.path.join(self.tmp.name, "b.jsonl")))
        result = gateway.call(ToolCall(
            "db", "query", {"environment": "staging", "table": "users"},
            environment="staging"))
        self.assertTrue(result["allowed"])
        self.assertEqual(result["result"]["rows"], 12)
        self.assertFalse(result["result"]["authenticated"])

    def test_rows_returned_with_credential_authenticated_true(self):
        result = self.gateway.call(ToolCall(
            "db", "query", {"environment": "staging", "table": "users"},
            environment="staging"))
        self.assertTrue(result["allowed"])
        self.assertEqual(result["result"]["rows"], 12)
        self.assertTrue(result["result"]["authenticated"])


class TestEnvMismatchCharged(GatewayFixture):
    """Finding 9: env-mismatch denials happened before the budget check,
    so they looped for free."""

    def test_env_mismatch_calls_consume_budget(self):
        self.gateway.budgets = BudgetManager(Budget(max_calls=100))
        for _ in range(5):
            result = self.gateway.call(ToolCall(
                "db", "query", {"environment": "prod", "table": "users"},
                environment="staging"))
            self.assertFalse(result["allowed"])
            self.assertIn("mismatch", result["reason"])
        self.assertEqual(self.gateway.budgets.calls, 5)

    def test_env_mismatch_loop_hits_budget_ceiling(self):
        self.gateway.budgets = BudgetManager(Budget(max_calls=3))
        for _ in range(3):
            self.gateway.call(ToolCall(
                "db", "query", {"environment": "prod", "table": "users"},
                environment="staging"))
        blocked = self.gateway.call(ToolCall(
            "db", "query", {"environment": "prod", "table": "users"},
            environment="staging"))
        self.assertFalse(blocked["allowed"])
        self.assertIn("budget", blocked["reason"])

    def test_malformed_calls_consume_budget(self):
        self.gateway.budgets = BudgetManager(Budget(max_calls=2))
        self.gateway.call(ToolCall("files", "list", None))
        self.gateway.call(ToolCall("files", "list", "x"))
        self.assertEqual(self.gateway.budgets.calls, 2)
        blocked = self.gateway.call(ToolCall("files", "list", {"path": "."}))
        self.assertFalse(blocked["allowed"])
        self.assertIn("budget", blocked["reason"])


class TestMalformedFuzz(unittest.TestCase):
    """Finding 1 (fuzz): extend the adversarial fuzzing to malformed
    argument shapes so 'never raises' is actually tested."""

    SEED = 20261112

    def test_malformed_args_never_raise(self):
        rng = random.Random(self.SEED)
        policy = load_demo_policy()
        bad_values = [123, None, ["x"], {"a": 1}, ("x",), 3.14, True,
                      b"bytes", {"nested": [1, {"deep": (2,)}]}]
        with tempfile.TemporaryDirectory() as tmp:
            ws = os.path.join(tmp, "ws")
            os.makedirs(ws)
            with open(os.path.join(ws, "notes.txt"), "w") as fh:
                fh.write("hello\n")
            with open(os.path.join(ws, "binary.bin"), "wb") as fh:
                fh.write(b"\x00\xff\xfe binary")
            gateway = Gateway(
                policy=policy, tools=FakeTools(ws),
                broker=SecretBroker(scopes=policy.secret_scopes,
                                    source={"AGENTSHIELD_SECRET_DB_PASSWORD": "s3cr3t"}),
                approvals=ApprovalStore(), budgets=BudgetManager(Budget()),
                audit=AuditLog(os.path.join(tmp, "a.jsonl"),
                               redact=lambda t: t))
            for trial in range(200):
                tool = rng.choice(["files", "db", "deploy", "shell", ""])
                action = rng.choice(["read", "list", "delete", "query", "run", ""])
                args = {}
                if rng.random() < 0.8:
                    args["path"] = rng.choice(bad_values + ["notes.txt", "binary.bin"])
                if rng.random() < 0.5:
                    args["table"] = rng.choice(bad_values + ["users"])
                if rng.random() < 0.5:
                    args["environment"] = rng.choice(bad_values + ["staging"])
                if rng.random() < 0.3:
                    args = rng.choice([None, "x", ["a"], 42])
                call = ToolCall(tool, action, args,
                                environment=rng.choice(["staging", 123, None]),
                                actor=rng.choice(["agent", 123, None, object()]))
                result = gateway.call(call)
                self.assertIsInstance(result, dict)
                self.assertIn("allowed", result)
                decision = gateway.explain(call)
                self.assertIsInstance(decision.allowed, bool)


if __name__ == "__main__":
    unittest.main()
