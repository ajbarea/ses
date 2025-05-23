"""
Unit tests for the SecurityExpertSystem implementation using CLIPS.
Tests focus on fact assertion, evaluation workflow, and result processing.
"""

import sys
import types
import unittest
from unittest.mock import MagicMock, patch

# Create mock CLIPS environment if CLIPS module is not available
if "clips" not in sys.modules:
    clips_module = types.SimpleNamespace(
        Environment=lambda: MagicMock(),
        CLIPSError=Exception,
    )
    sys.modules["clips"] = clips_module

from clips_evaluator import SecurityExpertSystem


class TestClipsEvaluator(unittest.TestCase):
    """Tests the SecurityExpertSystem's core functionality using mocked CLIPS environment."""

    def setUp(self):
        # Initialize expert system with mocked CLIPS environment
        self.expert_system = SecurityExpertSystem(rules_dir=None)
        self.mock_env = MagicMock()
        self.expert_system.env = self.mock_env
        # Enable fact assertion validation on mock environment
        self.mock_env.assert_string = MagicMock()

    def test_convert_patch_metrics_asserts_expected_facts(self):
        """Verifies patch status metrics are correctly converted to CLIPS facts."""
        data = {"patch": {"status": "out-of-date", "hotfixes": ["KB1", "KB2"]}}
        self.expert_system.convert_metrics_to_facts(data)
        # Expect one assert_string call for patch-status
        fact_call = '(patch-status (status "out-of-date") (hotfixes "KB1" "KB2"))'
        self.mock_env.assert_string.assert_any_call(fact_call)

    def test_convert_firewall_metrics_asserts_expected_fact(self):
        """Verifies firewall profile settings are correctly converted to CLIPS facts."""
        data = {
            "firewall": {
                "profiles": {"domain": "ON", "private": "OFF", "public": "OFF"}
            }
        }
        self.expert_system.convert_metrics_to_facts(data)
        fact_call = '(firewall (domain "ON") (private "OFF") (public "OFF"))'
        self.mock_env.assert_string.assert_any_call(fact_call)

    def test_evaluate_uses_internal_methods(self):
        """Validates the complete evaluation workflow including fact conversion,
        rule execution, and result processing."""
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
        # Verify result structure
        self.assertIn("score", result)
        self.assertIn("grade", result)
        self.assertIn("summary", result)
        self.assertIn("findings", result)
        self.assertIn("rules_fired", result)
        self.assertIn("explanations", result)


if __name__ == "__main__":
    unittest.main()
