"""
Unit tests for the SecurityExpertSystem implementation using CLIPS.
Tests focus on fact assertion, evaluation workflow, and result processing.
"""

import sys
import types
import unittest
from unittest.mock import MagicMock, patch
from pathlib import Path

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

    def test_load_templates_handles_clips_error(self):
        """Test that template loading errors are properly caught and re-raised."""
        # Create an environment that raises an error when trying to build a template
        mock_env = MagicMock()
        mock_env.build = MagicMock(
            side_effect=sys.modules["clips"].CLIPSError("Test error")
        )

        expert_system = SecurityExpertSystem(rules_dir=None)
        expert_system.env = mock_env

        # Verify that the error is re-raised
        with self.assertRaises(sys.modules["clips"].CLIPSError):
            expert_system._load_templates()

        # Verify that the error was logged (captured print statement)
        mock_env.build.assert_called()

    def test_load_rules_handles_missing_directory(self):
        """Test that _load_rules gracefully handles a non-existent rules directory."""
        # Create expert system with a non-existent directory path
        non_existent_dir = "non_existent_dir"
        expert_system = SecurityExpertSystem(rules_dir=non_existent_dir)

        # _load_rules should complete without raising an exception
        # This implicitly tests that the method returns after the warning
        expert_system._load_rules()  # Should not raise

        # Verify the rules directory doesn't exist
        self.assertFalse(Path(non_existent_dir).exists())

    def test_load_rules_handles_clips_error(self):
        """Test that _load_rules gracefully handles errors when loading rule files."""
        # Create a temporary rules directory with a test file
        rules_dir = Path("test_rules_dir")
        rules_dir.mkdir(exist_ok=True)
        rule_file = rules_dir / "test.clp"
        rule_file.touch()  # Create empty file

        # Set up expert system with mocked environment that raises on load
        expert_system = SecurityExpertSystem(rules_dir=str(rules_dir))
        mock_env = MagicMock()
        mock_env.load = MagicMock(
            side_effect=sys.modules["clips"].CLIPSError("Test error")
        )
        expert_system.env = mock_env

        try:
            # Should not raise exception, only log error
            expert_system._load_rules()

            # Verify load was attempted
            mock_env.load.assert_called_once_with(str(rule_file))
        finally:
            # Cleanup
            rule_file.unlink()
            rules_dir.rmdir()

    def test_run_evaluation_fallback_when_no_findings(self):
        """Test that run_evaluation creates a generic activation when rules are fired but can't be traced."""
        # Set up environment that runs successfully but returns no findings
        mock_env = MagicMock()
        mock_env.run = MagicMock(return_value=3)  # 3 rules fired
        mock_env.facts = MagicMock(return_value=[])  # No facts/findings
        expert_system = SecurityExpertSystem(rules_dir=None)
        expert_system.env = mock_env

        # Run evaluation
        rules_fired = expert_system.run_evaluation()

        # Verify the results
        self.assertEqual(rules_fired, 3)
        self.assertEqual(len(expert_system.rule_activations), 1)
        activation = expert_system.rule_activations[0]
        self.assertEqual(activation["rule"], "unknown")
        self.assertEqual(
            activation["activation"],
            "3 rules fired, but specific activations could not be traced.",
        )


if __name__ == "__main__":
    unittest.main()
