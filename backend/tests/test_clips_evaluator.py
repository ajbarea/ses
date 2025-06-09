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
        """Test that patch metrics are properly converted to CLIPS facts."""
        data = {"patch": {"status": "out-of-date", "hotfixes": ["KB1", "KB2"]}}
        self.expert_system.convert_metrics_to_facts(data)
        fact_call = '(patch-status (status "out-of-date") (hotfixes "KB1" "KB2"))'
        self.mock_env.assert_string.assert_any_call(fact_call)

    def test_convert_firewall_metrics_asserts_expected_fact(self):
        """Test that firewall metrics are properly converted to CLIPS facts."""
        data = {
            "firewall": {
                "profiles": {"domain": "ON", "private": "OFF", "public": "OFF"}
            }
        }
        self.expert_system.convert_metrics_to_facts(data)
        fact_call = '(firewall (domain "ON") (private "OFF") (public "OFF"))'
        self.mock_env.assert_string.assert_any_call(fact_call)

    def test_evaluate_uses_internal_methods(self):
        """Test that evaluate() calls the expected sequence of internal methods."""
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

    def test_evaluate_grade_excellent(self):
        """Test that a score of 95 results in an 'Excellent' grade."""
        dummy_metrics = {"any": "value"}
        with patch.object(self.expert_system, "convert_metrics_to_facts"), patch.object(
            self.expert_system, "run_evaluation", return_value=0
        ), patch.object(
            self.expert_system, "get_findings", return_value=[]
        ), patch.object(
            self.expert_system, "get_score", return_value=95
        ), patch.object(
            self.expert_system, "get_rule_trace", return_value=[]
        ):
            result = self.expert_system.evaluate(dummy_metrics)
            self.assertEqual(result["grade"], "Excellent")

    def test_evaluate_grade_good(self):
        """Test that a score of 85 results in a 'Good' grade."""
        dummy_metrics = {"any": "value"}
        with patch.object(self.expert_system, "convert_metrics_to_facts"), patch.object(
            self.expert_system, "run_evaluation", return_value=0
        ), patch.object(
            self.expert_system, "get_findings", return_value=[]
        ), patch.object(
            self.expert_system, "get_score", return_value=85
        ), patch.object(
            self.expert_system, "get_rule_trace", return_value=[]
        ):
            result = self.expert_system.evaluate(dummy_metrics)
            self.assertEqual(result["grade"], "Good")

    def test_evaluate_grade_fair(self):
        """Test that a score of 75 results in a 'Fair' grade."""
        dummy_metrics = {"any": "value"}
        with patch.object(self.expert_system, "convert_metrics_to_facts"), patch.object(
            self.expert_system, "run_evaluation", return_value=0
        ), patch.object(
            self.expert_system, "get_findings", return_value=[]
        ), patch.object(
            self.expert_system, "get_score", return_value=75
        ), patch.object(
            self.expert_system, "get_rule_trace", return_value=[]
        ):
            result = self.expert_system.evaluate(dummy_metrics)
            self.assertEqual(result["grade"], "Fair")

    def test_evaluate_grade_poor(self):
        """Test that a score of 55 results in a 'Poor' grade."""
        dummy_metrics = {"any": "value"}
        with patch.object(self.expert_system, "convert_metrics_to_facts"), patch.object(
            self.expert_system, "run_evaluation", return_value=0
        ), patch.object(
            self.expert_system, "get_findings", return_value=[]
        ), patch.object(
            self.expert_system, "get_score", return_value=55
        ), patch.object(
            self.expert_system, "get_rule_trace", return_value=[]
        ):
            result = self.expert_system.evaluate(dummy_metrics)
            self.assertEqual(result["grade"], "Poor")

    def test_evaluate_grade_critical_risk(self):
        """Test that a score of 35 results in a 'Critical Risk' grade."""
        dummy_metrics = {"any": "value"}
        with patch.object(self.expert_system, "convert_metrics_to_facts"), patch.object(
            self.expert_system, "run_evaluation", return_value=0
        ), patch.object(
            self.expert_system, "get_findings", return_value=[]
        ), patch.object(
            self.expert_system, "get_score", return_value=35
        ), patch.object(
            self.expert_system, "get_rule_trace", return_value=[]
        ):
            result = self.expert_system.evaluate(dummy_metrics)
            self.assertEqual(result["grade"], "Critical Risk")

    def test_load_templates_handles_clips_error(self):
        """Test that CLIPS errors during template loading are properly propagated."""
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
        """Test graceful handling when rules directory doesn't exist."""
        non_existent_dir = "non_existent_dir"
        expert_system = SecurityExpertSystem(rules_dir=non_existent_dir)
        expert_system._load_rules()
        self.assertFalse(Path(non_existent_dir).exists())

    def test_load_rules_handles_clips_error(self):
        """Test graceful handling of CLIPS errors during rule loading."""
        from pathlib import Path

        # Use existing clips_rules directory for test files
        rules_dir = Path("src") / "clips_rules"
        expert_system = SecurityExpertSystem(rules_dir=str(rules_dir))
        mock_env = MagicMock()
        mock_env.load = MagicMock(
            side_effect=sys.modules["clips"].CLIPSError("Test error")
        )
        expert_system.env = mock_env
        expert_system._load_rules()
        mock_env.load.assert_called()


class TestConvertMetricsToFacts(unittest.TestCase):
    """Tests the conversion of metric data to CLIPS facts."""

    def setUp(self):
        self.expert = SecurityExpertSystem(rules_dir=None)
        self.expert.env = MagicMock()
        self.expert.env.reset = MagicMock()
        self.expert.env.assert_string = MagicMock()

    def test_ports_to_open_port_facts(self):
        """Test conversion of port metrics to open-port facts."""
        data = {"ports": {"ports": [22, 80]}}
        self.expert.convert_metrics_to_facts(data)
        self.expert.env.assert_string.assert_any_call("(open-port (number 22))")
        self.expert.env.assert_string.assert_any_call("(open-port (number 80))")

    def test_services_to_service_facts(self):
        """Test conversion of service metrics to service facts."""
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
        """Test conversion of antivirus metrics to antivirus-product facts."""
        products = [{"name": "AVX", "state": 5}, {"name": "AVY", "state": None}]
        data = {"antivirus": {"products": products}}
        self.expert.convert_metrics_to_facts(data)
        self.expert.env.assert_string.assert_any_call(
            '(antivirus-product (name "AVX") (state 5))'
        )
        self.expert.env.assert_string.assert_any_call(
            '(antivirus-product (name "AVY") (state UNKNOWN))'
        )

    def test_antivirus_no_products(self):
        """Test antivirus status when no products are detected."""
        data = {"antivirus": {"products": []}}
        self.expert.convert_metrics_to_facts(data)

        # Verify the antivirus-info fact is asserted with correct values
        expected_fact = (
            "(antivirus-info "
            '(status "disabled") '
            '(definitions "up-to-date") '
            '(real-time-protection "disabled")'
            ")"
        )
        self.expert.env.assert_string.assert_any_call(expected_fact)

        # Also verify no antivirus-product facts were created
        for call in self.expert.env.assert_string.call_args_list:
            self.assertNotIn("antivirus-product", str(call))

    def test_antivirus_all_products_disabled(self):
        """Test antivirus status when all products are disabled."""
        products = [{"name": "AVX", "state": 1}, {"name": "AVY", "state": 200}]
        data = {"antivirus": {"products": products}}
        self.expert.convert_metrics_to_facts(data)
        self.expert.env.assert_string.assert_any_call(
            '(antivirus-info (status "disabled") (definitions "up-to-date") (real-time-protection "disabled"))'
        )

    def test_antivirus_partial_products_disabled(self):
        """Test antivirus status when some products are disabled."""
        products = [{"name": "AVX", "state": 1}, {"name": "AVY", "state": 400000}]
        data = {"antivirus": {"products": products}}
        self.expert.convert_metrics_to_facts(data)
        self.expert.env.assert_string.assert_any_call(
            '(antivirus-info (status "partial") (definitions "up-to-date") (real-time-protection "disabled"))'
        )

    def test_antivirus_all_products_enabled(self):
        """Test antivirus status when all products are enabled."""
        products = [{"name": "AVX", "state": 397500}, {"name": "AVY", "state": 400000}]
        data = {"antivirus": {"products": products}}
        self.expert.convert_metrics_to_facts(data)
        self.expert.env.assert_string.assert_any_call(
            '(antivirus-info (status "enabled") (definitions "up-to-date") (real-time-protection "enabled"))'
        )

    def test_antivirus_definitions_out_of_date(self):
        """Test antivirus definitions status when some products have undefined state."""
        products = [{"name": "AVX", "state": 397500}, {"name": "AVY", "state": None}]
        data = {"antivirus": {"products": products}}
        self.expert.convert_metrics_to_facts(data)
        self.expert.env.assert_string.assert_any_call(
            '(antivirus-info (status "partial") (definitions "out-of-date") (real-time-protection "disabled"))'
        )

    def test_password_policy_to_password_policy_fact(self):
        """Test conversion of password policy metrics to password-policy facts."""
        policy = {"min_password_length": 5, "max_password_age": 15}
        data = {"password_policy": {"policy": policy}}
        self.expert.convert_metrics_to_facts(data)
        self.expert.env.assert_string.assert_any_call(
            "(password-policy (min-password-length 5) (max-password-age 15))"
        )


class FakeFact(dict):
    """Helper class to simulate CLIPS facts for testing."""

    def __init__(self, template_name, **kwargs):
        super().__init__(kwargs)
        self.template = types.SimpleNamespace(name=template_name)


class TestExtractorsTracers(unittest.TestCase):
    """Tests for methods that extract information from CLIPS facts."""

    def setUp(self):
        self.expert = SecurityExpertSystem(rules_dir=None)
        self.expert.rule_activations = []

    def test_get_findings_only_returns_finding_facts(self):
        """Test that get_findings only processes facts of template 'finding'."""
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

        # Check only the basic properties that don't depend on score calculation
        self.assertEqual(findings[0]["rule"], "r1")
        self.assertEqual(findings[0]["level"], "warning")
        self.assertEqual(findings[0]["description"], "d1")
        self.assertEqual(findings[0]["recommendation"], "rec1")
        self.assertEqual(findings[0]["details"], ["a", "b"])

        # Verify score impact was added with default values for warning level
        self.assertEqual(findings[0]["score_impact"]["type"], "penalty")
        self.assertEqual(findings[0]["score_impact"]["value"], -10)
        self.assertEqual(findings[0]["score_text"], "-10 points")

    def test_get_score_with_final_score_fact(self):
        """Test that get_score uses the final score fact when available."""
        f = FakeFact("score", **{"value": "85", "type": "final"})
        self.expert.env.facts = lambda: [f]
        score = self.expert.get_score(base_score=50)
        self.assertEqual(score, 85)

    def test_get_score_with_penalty_facts_and_clamping(self):
        """Test score calculation from penalty facts with clamping to prevent negative scores."""
        f1 = FakeFact("score", **{"value": "-150", "type": "penalty"})
        f2 = FakeFact("score", **{"value": "30", "type": "penalty"})
        self.expert.env.facts = lambda: [f1, f2]
        score = self.expert.get_score()
        self.assertEqual(score, 0)

    def test_get_score_falls_back_to_findings(self):
        """Test that get_score uses base score when no score facts exist."""
        self.expert.env.facts = lambda: []
        # The implementation no longer falls back to findings for score calculation
        # It just returns the base score when no score facts exist
        score = self.expert.get_score(base_score=100)
        self.assertEqual(score, 100)

    def test_get_rule_trace_returns_activations(self):
        """Test that get_rule_trace returns the stored rule activations."""
        self.expert.rule_activations = [{"rule": "r", "activation": "a"}]
        trace = self.expert.get_rule_trace()
        self.assertIs(trace, self.expert.rule_activations)


class TestRunEvaluation(unittest.TestCase):
    """Tests for the run_evaluation method."""

    def setUp(self):
        self.expert = SecurityExpertSystem(rules_dir=None)
        self.mock_env = MagicMock()
        self.expert.env = self.mock_env
        self.mock_env.facts = MagicMock(return_value=[])

    def test_watch_supported_traces_rules(self):
        """Test rule tracing when watch/unwatch are supported."""
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
        """Test fallback to findings-based rule tracing when watch raises AttributeError."""
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
        """Test fallback to findings-based rule tracing when watch raises TypeError."""
        self.mock_env.watch = MagicMock(side_effect=TypeError)
        self.mock_env.run = MagicMock(return_value=3)
        findings = [{"rule": "rX", "description": "descX"}]
        self.expert.get_findings = MagicMock(return_value=findings)
        fired = self.expert.run_evaluation()
        self.assertEqual(fired, 3)
        self.assertEqual(len(self.expert.rule_activations), 1)
        self.assertEqual(
            self.expert.rule_activations[0]["activation"], "Rule activated: rX - descX"
        )

    def test_watch_supported_no_new_facts_appends_unknown(self):
        """Test handling when no rule activations are detected but rules fired."""
        self.mock_env.watch = MagicMock()
        self.mock_env.unwatch = MagicMock()
        self.mock_env.run = MagicMock(return_value=4)
        facts = []
        self.mock_env.facts = MagicMock(side_effect=[facts, facts])
        self.expert.get_findings = MagicMock(return_value=[])
        fired = self.expert.run_evaluation()
        self.assertEqual(fired, 4)
        self.assertEqual(len(self.expert.rule_activations), 1)
        entry = self.expert.rule_activations[0]
        self.assertEqual(entry["rule"], "unknown")
        self.assertIn("4 rules fired", entry["activation"])

    def test_unwatch_raises_error_fallbacks_to_findings(self):
        """Test fallback to findings-based rule tracing when unwatch raises an exception."""
        self.mock_env.watch = MagicMock()
        self.mock_env.unwatch = MagicMock(side_effect=AttributeError)

        def run_side_effect():
            print("FIRE 1 ruleZ")
            return 1

        self.mock_env.run = MagicMock(side_effect=run_side_effect)
        findings = [{"rule": "rZ", "description": "descZ"}]
        self.expert.get_findings = MagicMock(return_value=findings)
        fired = self.expert.run_evaluation()
        self.assertEqual(fired, 1)
        self.assertEqual(
            self.expert.rule_activations[0]["activation"], "Rule activated: rZ - descZ"
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
