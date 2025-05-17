"""
Unit tests for the CLIPS-based SecurityExpertSystem evaluator.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

try:
    from clips_evaluator import SecurityExpertSystem

    CLIPS_AVAILABLE = True
except ImportError:
    CLIPS_AVAILABLE = False


@unittest.skipIf(not CLIPS_AVAILABLE, "PyCLIPS not installed")
class TestClipsEvaluator(unittest.TestCase):
    """Test cases for the CLIPS SecurityExpertSystem."""

    def setUp(self):
        """Instantiate the SecurityExpertSystem before each test."""
        self.expert_system = SecurityExpertSystem()

    def test_convert_patch_metrics(self):
        """Test conversion of patch metrics into CLIPS facts."""
        data = {
            "patch": {
                "status": "out-of-date",
                "hotfixes": ["KB4569745", "KB4565503"],
            }
        }
        self.expert_system.convert_metrics_to_facts(data)
        facts = [
            f
            for f in self.expert_system.env.facts()
            if f.template.name == "patch-status"
        ]
        self.assertTrue(facts, "Patch status fact was not created")
        fact = facts[0]
        self.assertEqual(fact["status"], "out-of-date")
        self.assertEqual(list(fact["hotfixes"]), ["KB4569745", "KB4565503"])

    def test_convert_firewall_metrics(self):
        """Test conversion of firewall metrics into CLIPS facts."""
        data = {
            "firewall": {
                "profiles": {"domain": "ON", "private": "OFF", "public": "OFF"},
            }
        }
        self.expert_system.convert_metrics_to_facts(data)
        facts = [
            f for f in self.expert_system.env.facts() if f.template.name == "firewall"
        ]
        self.assertTrue(facts, "Firewall fact was not created")
        fact = facts[0]
        self.assertEqual(fact["domain"], "ON")
        self.assertEqual(fact["private"], "OFF")
        self.assertEqual(fact["public"], "OFF")

    def test_patch_rules(self):
        """Verify critical finding for missing patches."""
        result = self.expert_system.evaluate(
            {"patch": {"status": "out-of-date", "hotfixes": []}}
        )
        findings = [
            f
            for f in result["findings"]
            if f["rule"] == "patch_status" and f["level"] == "critical"
        ]
        self.assertTrue(findings, "Critical patch finding was not created")
        self.assertLess(
            result["score"], 100, "Score should be reduced for missing patches"
        )

    def test_firewall_rules(self):
        """Verify critical finding for disabled firewall profiles."""
        result = self.expert_system.evaluate(
            {
                "firewall": {
                    "profiles": {"domain": "OFF", "private": "OFF", "public": "OFF"}
                }
            }
        )
        findings = [
            f
            for f in result["findings"]
            if f["rule"] == "firewall_all_disabled" and f["level"] == "critical"
        ]
        self.assertTrue(findings, "Critical firewall finding was not created")
        self.assertLess(
            result["score"], 100, "Score should be reduced for disabled firewall"
        )


if __name__ == "__main__":
    unittest.main()
