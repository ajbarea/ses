"""
Unit tests for the security evaluation system.
Validates both standard and CLIPS-based evaluation methods, ensuring proper
result structure and type consistency across different evaluation modes.
"""

from unittest.mock import patch
import unittest
from rules import evaluate, CLIPS_AVAILABLE

# Reference metrics representing a baseline secure system configuration
# Used to generate consistent test outputs
DUMMY_METRICS = {
    "patch": {"hotfixes": ["KB1"], "status": "up-to-date"},
    "ports": {"ports": []},
    "services": {"services": []},
    "firewall": {"profiles": {"domain": "ON", "private": "ON", "public": "ON"}},
    "antivirus": {"products": []},
    "password_policy": {"policy": {"min_password_length": 8, "max_password_age": 90}},
}


class TestEvaluation(unittest.TestCase):
    @patch("rules._evaluate_legacy")
    def test_standard_evaluation_output(self, mock_legacy):
        """Validates structure and types of standard evaluation results.
        Tests the non-CLIPS evaluation path using mocked legacy evaluator."""
        mock_legacy.return_value = {
            "score": 100,
            "grade": "Excellent",
            "summary": "",
            "findings": [],
        }
        result = evaluate(DUMMY_METRICS, use_clips=False)
        self.assertIn("score", result)
        self.assertIn("grade", result)
        self.assertIn("summary", result)
        self.assertIsInstance(result["score"], (int, float))
        self.assertIsInstance(result.get("findings"), list)
        mock_legacy.assert_called_once_with(DUMMY_METRICS)

    @unittest.skipIf(
        not CLIPS_AVAILABLE, "Skipping CLIPS tests: PyCLIPS package required"
    )
    @patch("rules._evaluate_clips")
    def test_clips_evaluation_output(self, mock_clips):
        """Validates structure and types of CLIPS-based evaluation results.
        Tests the CLIPS evaluation path using mocked CLIPS evaluator."""
        mock_clips.return_value = {
            "score": 95,
            "grade": "Good",
            "summary": "Test",
            "findings": [],
            "rules_fired": 1,
        }
        result = evaluate(DUMMY_METRICS, use_clips=True)
        self.assertIn("score", result)
        self.assertIn("grade", result)
        self.assertIn("summary", result)
        self.assertIsInstance(result.get("findings"), list)
        self.assertIn("rules_fired", result)
        mock_clips.assert_called_once_with(DUMMY_METRICS)


if __name__ == "__main__":
    unittest.main()
