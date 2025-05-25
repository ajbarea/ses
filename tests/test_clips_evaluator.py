import sys
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Create mock CLIPS environment if CLIPS module is not available
if "clips" not in sys.modules:
    clips_module = types.SimpleNamespace(
        Environment=lambda: MagicMock(),
        CLIPSError=Exception,
    )
    sys.modules["clips"] = clips_module

from src.clips_evaluator import SecurityExpertSystem


class TestClipsEvaluator(unittest.TestCase):
    """Tests the SecurityExpertSystem's core functionality using mocked CLIPS environment."""

    def setUp(self):
        self.expert_system = SecurityExpertSystem(rules_dir=None)
        self.mock_env = MagicMock()
        self.expert_system.env = self.mock_env
        self.mock_env.assert_string = MagicMock()

    def test_convert_patch_metrics_asserts_expected_facts(self):
        data = {"patch": {"status": "out-of-date", "hotfixes": ["KB1", "KB2"]}}
        self.expert_system.convert_metrics_to_facts(data)
        fact_call = '(patch-status (status "out-of-date") (hotfixes "KB1" "KB2"))'
        self.mock_env.assert_string.assert_any_call(fact_call)

    def test_convert_firewall_metrics_asserts_expected_fact(self):
        data = {
            "firewall": {
                "profiles": {"domain": "ON", "private": "OFF", "public": "OFF"}
            }
        }
        self.expert_system.convert_metrics_to_facts(data)
        fact_call = '(firewall (domain "ON") (private "OFF") (public "OFF"))'
        self.mock_env.assert_string.assert_any_call(fact_call)

    def test_evaluate_uses_internal_methods(self):
        dummy_metrics = {"any": "value"}
        with patch.object(
            self.expert_system, "convert_metrics_to_facts"
        ) as mock_convert, patch.object(
            self.expert_system, "run_evaluation", return_value=2
        ) as mock_run, patch.object(
            self.expert_system,
            "get_findings",
            return_value=[{"rule-name": "r", "level": "info", "description": "d"}],
        ) as mock_findings, patch.object(
            self.expert_system, "get_score", return_value=80
        ) as mock_score, patch.object(
            self.expert_system, "get_rule_trace", return_value=["r1", "r2"]
        ) as mock_trace:
            result = self.expert_system.evaluate(dummy_metrics)
            mock_convert.assert_called_once_with(dummy_metrics)
            mock_run.assert_called_once()
            mock_findings.assert_called_once()
            mock_score.assert_called_once()
            mock_trace.assert_called_once()
            self.assertIn("score", result)
            self.assertIn("grade", result)
            self.assertIn("summary", result)
            self.assertIn("findings", result)
            self.assertIn("rules_fired", result)
            self.assertIn("explanations", result)

    def test_load_templates_handles_clips_error(self):
        mock_env = MagicMock()
        mock_env.build = MagicMock(
            side_effect=sys.modules["clips"].CLIPSError("Test error")
        )
        expert_system = SecurityExpertSystem(rules_dir=None)
        expert_system.env = mock_env
        with self.assertRaises(sys.modules["clips"].CLIPSError):
            expert_system._load_templates()
        mock_env.build.assert_called()

    def test_load_rules_handles_missing_directory(self):
        non_existent_dir = "non_existent_dir"
        expert_system = SecurityExpertSystem(rules_dir=non_existent_dir)
        expert_system._load_rules()
        self.assertFalse(Path(non_existent_dir).exists())

    def test_load_rules_handles_clips_error(self):
        from pathlib import Path

        # Use existing clips_rules directory for test files
        rules_dir = Path("clips_rules")
        expert_system = SecurityExpertSystem(rules_dir=str(rules_dir))
        mock_env = MagicMock()
        mock_env.load = MagicMock(
            side_effect=sys.modules["clips"].CLIPSError("Test error")
        )
        expert_system.env = mock_env
        expert_system._load_rules()
        mock_env.load.assert_called()


class TestConvertMetricsToFacts(unittest.TestCase):
    def setUp(self):
        self.expert = SecurityExpertSystem(rules_dir=None)
        self.expert.env = MagicMock()
        self.expert.env.reset = MagicMock()
        self.expert.env.assert_string = MagicMock()

    def test_ports_to_open_port_facts(self):
        data = {"ports": {"ports": [22, 80]}}
        self.expert.convert_metrics_to_facts(data)
        self.expert.env.assert_string.assert_any_call("(open-port (number 22))")
        self.expert.env.assert_string.assert_any_call("(open-port (number 80))")

    def test_services_to_service_facts(self):
        services = [
            {"name": "SvcA", "state": "Running"},
            {"name": "SvcB", "state": "Stopped"},
        ]
        data = {"services": {"services": services}}
        self.expert.convert_metrics_to_facts(data)
        self.expert.env.assert_string.assert_any_call(
            '(service (name "SvcA") (state "Running"))'
        )
        self.expert.env.assert_string.assert_any_call(
            '(service (name "SvcB") (state "Stopped"))'
        )

    def test_antivirus_to_antivirus_product_facts(self):
        products = [{"name": "AVX", "state": 5}, {"name": "AVY", "state": None}]
        data = {"antivirus": {"products": products}}
        self.expert.convert_metrics_to_facts(data)
        self.expert.env.assert_string.assert_any_call(
            '(antivirus-product (name "AVX") (state 5))'
        )
        self.expert.env.assert_string.assert_any_call(
            '(antivirus-product (name "AVY") (state UNKNOWN))'
        )

    def test_password_policy_to_password_policy_fact(self):
        policy = {"min_password_length": 5, "max_password_age": 15}
        data = {"password_policy": {"policy": policy}}
        self.expert.convert_metrics_to_facts(data)
        self.expert.env.assert_string.assert_any_call(
            "(password-policy (min-password-length 5) (max-password-age 15))"
        )


class FakeFact(dict):
    def __init__(self, template_name, **kwargs):
        super().__init__(kwargs)
        self.template = types.SimpleNamespace(name=template_name)


class TestExtractorsTracers(unittest.TestCase):
    def setUp(self):
        self.expert = SecurityExpertSystem(rules_dir=None)
        self.expert.rule_activations = []

    def test_get_findings_only_returns_finding_facts(self):
        f1 = FakeFact(
            "finding",
            **{
                "rule-name": "r1",
                "level": "warning",
                "description": "d1",
                "recommendation": "rec1",
                "details": ("a", "b"),
            }
        )
        f2 = FakeFact("other", **{"foo": "bar"})
        self.expert.env.facts = lambda: [f1, f2]
        findings = self.expert.get_findings()
        self.assertEqual(len(findings), 1)
        self.assertDictEqual(
            findings[0],
            {
                "rule": "r1",
                "level": "warning",
                "description": "d1",
                "recommendation": "rec1",
                "details": ["a", "b"],
            },
        )

    def test_get_score_with_final_score_fact(self):
        f = FakeFact("score", **{"value": "85", "type": "final"})
        self.expert.env.facts = lambda: [f]
        score = self.expert.get_score(base_score=50)
        self.assertEqual(score, 85)

    def test_get_score_with_penalty_facts_and_clamping(self):
        f1 = FakeFact("score", **{"value": "-150", "type": "penalty"})
        f2 = FakeFact("score", **{"value": "30", "type": "penalty"})
        self.expert.env.facts = lambda: [f1, f2]
        score = self.expert.get_score()
        self.assertEqual(score, 0)

    def test_get_score_falls_back_to_findings(self):
        self.expert.env.facts = lambda: []
        self.expert.get_findings = lambda: [{"level": "critical"}, {"level": "info"}]
        score = self.expert.get_score()
        self.assertEqual(score, 65)

    def test_get_rule_trace_returns_activations(self):
        self.expert.rule_activations = [{"rule": "r", "activation": "a"}]
        trace = self.expert.get_rule_trace()
        self.assertIs(trace, self.expert.rule_activations)


class TestRunEvaluation(unittest.TestCase):
    def setUp(self):
        self.expert = SecurityExpertSystem(rules_dir=None)
        self.mock_env = MagicMock()
        self.expert.env = self.mock_env
        self.mock_env.facts = MagicMock(return_value=[])

    def test_watch_supported_traces_rules(self):
        self.mock_env.watch = MagicMock()
        self.mock_env.unwatch = MagicMock()

        def run_side_effect():
            print("FIRE 1 ruleA")
            print("FIRE 2 ruleB")
            return 2

        self.mock_env.run = MagicMock(side_effect=run_side_effect)
        fired = self.expert.run_evaluation()
        self.assertEqual(fired, 2)
        self.assertEqual(len(self.expert.rule_activations), 2)
        self.assertEqual(self.expert.rule_activations[0]["rule"], "ruleA")
        self.assertIn("FIRE 1 ruleA", self.expert.rule_activations[0]["activation"])
        self.assertEqual(self.expert.rule_activations[1]["rule"], "ruleB")

    def test_watch_unsupported_fallbacks_to_findings(self):
        self.mock_env.watch = MagicMock(side_effect=AttributeError)
        self.mock_env.run = MagicMock(return_value=5)
        findings = [
            {"rule": "r1", "description": "desc1"},
            {"rule": "r2", "description": "desc2"},
        ]
        self.expert.get_findings = MagicMock(return_value=findings)
        fired = self.expert.run_evaluation()
        self.assertEqual(fired, 5)
        self.assertEqual(len(self.expert.rule_activations), 2)
        self.assertEqual(
            self.expert.rule_activations[0]["activation"], "Rule activated: r1 - desc1"
        )
        self.assertEqual(
            self.expert.rule_activations[1]["activation"], "Rule activated: r2 - desc2"
        )

    def test_watch_type_error_fallbacks_to_findings(self):
        """If watch raises TypeError, fallback behavior matches AttributeError fallback"""
        # Simulate watch unsupported via TypeError
        self.mock_env.watch = MagicMock(side_effect=TypeError)
        # env.run still returns a rule fire count
        self.mock_env.run = MagicMock(return_value=3)
        # Prepare findings for fallback trace
        findings = [{"rule": "rX", "description": "descX"}]
        self.expert.get_findings = MagicMock(return_value=findings)
        fired = self.expert.run_evaluation()
        self.assertEqual(fired, 3)
        # Fallback should add one activation entry
        self.assertEqual(len(self.expert.rule_activations), 1)
        self.assertEqual(
            self.expert.rule_activations[0]["activation"], "Rule activated: rX - descX"
        )

    def test_watch_supported_no_new_facts_appends_unknown(self):
        """If watch/unwatch succeed but no new activations are found, append 'unknown' rule entry"""
        # Simulate watch/unwatch supported
        self.mock_env.watch = MagicMock()
        self.mock_env.unwatch = MagicMock()
        # Run returns 4 rules fired
        self.mock_env.run = MagicMock(return_value=4)
        # facts before and after are identical (no new facts)
        facts = []
        self.mock_env.facts = MagicMock(side_effect=[facts, facts])
        # Avoid further env.facts calls by returning no findings
        self.expert.get_findings = MagicMock(return_value=[])
        fired = self.expert.run_evaluation()
        self.assertEqual(fired, 4)
        # Should have one 'unknown' activation entry
        self.assertEqual(len(self.expert.rule_activations), 1)
        entry = self.expert.rule_activations[0]
        self.assertEqual(entry["rule"], "unknown")
        self.assertIn("4 rules fired", entry["activation"])

    def test_unwatch_raises_error_fallbacks_to_findings(self):
        """If unwatch raises an exception, fallback to findings trace"""
        # Simulate watch supported and unwatch raising AttributeError
        self.mock_env.watch = MagicMock()
        self.mock_env.unwatch = MagicMock(side_effect=AttributeError)

        # env.run outputs a FIRE line but will not be processed due to unwatch error
        def run_side_effect():
            print("FIRE 1 ruleZ")
            return 1

        self.mock_env.run = MagicMock(side_effect=run_side_effect)
        # Provide fallback findings
        findings = [{"rule": "rZ", "description": "descZ"}]
        self.expert.get_findings = MagicMock(return_value=findings)
        fired = self.expert.run_evaluation()
        self.assertEqual(fired, 1)
        # Fallback should use findings activation since unwatch broke
        self.assertEqual(
            self.expert.rule_activations[0]["activation"], "Rule activated: rZ - descZ"
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
