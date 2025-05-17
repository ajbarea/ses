"""Unit tests for standard and CLIPS-based security evaluation.

These tests check that the evaluation functions return results with the
expected structure and data types.
"""

import unittest
from scanner import (
    get_patch_status,
    get_open_ports,
    get_running_services,
    get_firewall_status,
    get_antivirus_status,
    get_password_policy,
)
from rules import evaluate, CLIPS_AVAILABLE


class TestEvaluation(unittest.TestCase):
    """Unit tests for standard and CLIPS-based security evaluation."""

    def setUp(self):
        """Gather system metrics before each test."""
        self.metrics = {
            "patch": get_patch_status(),
            "ports": get_open_ports(),
            "services": get_running_services(),
            "firewall": get_firewall_status(),
            "antivirus": get_antivirus_status(),
            "password_policy": get_password_policy(),
        }

    def test_standard_evaluation_output(self):
        """Test that standard evaluation returns expected keys and types."""
        result = evaluate(self.metrics, use_clips=False)
        self.assertIn("score", result)
        self.assertIn("grade", result)
        self.assertIn("summary", result)
        self.assertIsInstance(result["score"], (int, float))
        self.assertIsInstance(result.get("findings"), list)

    @unittest.skipIf(not CLIPS_AVAILABLE, "PyCLIPS not installed")
    def test_clips_evaluation_output(self):
        """Test that CLIPS evaluation returns expected keys and types."""
        result = evaluate(self.metrics, use_clips=True)
        self.assertIn("score", result)
        self.assertIn("grade", result)
        self.assertIn("summary", result)
        self.assertIsInstance(result.get("findings"), list)
        # rules_fired may be int or list depending on implementation
        self.assertTrue("rules_fired" in result)


if __name__ == "__main__":
    unittest.main()
