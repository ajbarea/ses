"""
Integration tests to verify consistency between CLIPS and legacy rule engines.

These tests ensure that both rule engines produce consistent evaluations
for the same security metrics, or document expected differences.
"""

import unittest
import json
from pathlib import Path
from unittest.mock import patch, Mock

# Check if CLIPS is available - needed for meaningful tests
try:
    import clips

    CLIPS_AVAILABLE = True
except ImportError:
    CLIPS_AVAILABLE = False

from src.rules import (
    evaluate,
)
from src.logging_config import setup_logging

# Setup minimal logging to avoid noise during tests
setup_logging(log_level="ERROR")


@unittest.skipIf(not CLIPS_AVAILABLE, "CLIPS is required for engine consistency tests")
class TestEngineConsistency(unittest.TestCase):
    """Tests to verify consistency between CLIPS and legacy rule engines."""

    def setUp(self):
        """Load test metrics from sample files."""
        self.metrics_dir = Path(__file__).parent / "metric_mocks"
        self.metrics_files = list(self.metrics_dir.glob("*.json"))

        # Ensure we have test metrics
        if not self.metrics_files:
            self.fail("No metric mock files found in tests/metric_mocks directory")

    def _get_key_differences(self, clips_result, legacy_result):
        """Find significant differences between evaluation results."""
        differences = {}

        # Compare scores
        score_diff = abs(clips_result.get("score", 0) - legacy_result.get("score", 0))
        if score_diff > 5:  # Allow minor differences in score calculation
            differences["score"] = {
                "clips": clips_result.get("score"),
                "legacy": legacy_result.get("score"),
                "difference": score_diff,
            }

        # Compare grades
        if clips_result.get("grade") != legacy_result.get("grade"):
            differences["grade"] = {
                "clips": clips_result.get("grade"),
                "legacy": legacy_result.get("grade"),
            }

        # Compare finding counts by level
        clips_findings = clips_result.get("findings", [])
        legacy_findings = legacy_result.get("findings", [])

        clips_by_level = self._count_findings_by_level(clips_findings)
        legacy_by_level = self._count_findings_by_level(legacy_findings)

        if clips_by_level != legacy_by_level:
            differences["finding_counts"] = {
                "clips": clips_by_level,
                "legacy": legacy_by_level,
            }

        return differences

    def _count_findings_by_level(self, findings):
        """Count findings by severity level."""
        counts = {"critical": 0, "warning": 0, "info": 0}
        for finding in findings:
            level = finding.get("level", "info")
            if level in counts:
                counts[level] += 1
        return counts

    def _get_complete_test_metrics(self):
        """Generate a complete set of test metrics with all required keys."""
        return {
            "antivirus": {
                "products": [
                    {"name": "Test Antivirus", "state": "enabled", "up_to_date": True}
                ]
            },
            "firewall": {"profiles": {"domain": "ON", "private": "ON", "public": "ON"}},
            "patch": {"status": "out-of-date", "hotfixes": []},
            "password_policy": {
                "policy": {
                    "min_password_length": 8,
                    "complexity": "enabled",
                    "history_size": 5,
                    "max_password_age": 90,
                    "lockout_threshold": 5,
                }
            },
            "ports": {"ports": [80, 443]},
            "services": {"services": [{"name": "test-service", "status": "running"}]},
        }

    def _load_and_complete_metrics(self, metrics_file):
        """Load JSON and ensure all required keys present."""
        with open(metrics_file, "r") as f:
            metrics = json.load(f)
        complete = self._get_complete_test_metrics()
        for k, v in complete.items():
            metrics.setdefault(k, v)
        return metrics

    def _extract_critical_rules(self, result):
        """Return set of critical rule names from evaluation result."""
        return {
            f.get("rule")
            for f in result.get("findings", [])
            if f.get("level") == "critical"
        }

    def _check_critical_consistency(self, issue, clips_set, legacy_set):
        if issue in clips_set and issue not in legacy_set:
            self.fail(
                f"Critical issue {issue} detected by CLIPS but not by legacy engine"
            )
        if issue in legacy_set and issue not in clips_set:
            self.fail(
                f"Critical issue {issue} detected by legacy engine but not by CLIPS"
            )

    def test_engine_consistency_for_all_samples(self):
        """Test CLIPS and legacy engines produce consistent results for all samples."""
        all_differences = {}

        for metrics_file in self.metrics_files:
            with open(metrics_file, "r") as f:
                metrics = json.load(f)

            # Ensure metrics contains all required keys in the expected format
            complete_metrics = self._get_complete_test_metrics()
            for key in complete_metrics:
                if key not in metrics:
                    metrics[key] = complete_metrics[key]

            # Force evaluation with both engines
            clips_result = evaluate(metrics, use_clips=True)
            legacy_result = evaluate(metrics, use_clips=False)

            # Find differences
            differences = self._get_key_differences(clips_result, legacy_result)
            if differences:
                all_differences[metrics_file.name] = differences

        # Fail immediately on any divergence
        if all_differences:
            differences_msg = json.dumps(all_differences, indent=2)
            self.fail(
                f"Differences between CLIPS and legacy engines: {differences_msg}"
            )

    def test_rule_count_consistency(self):
        """Test that both engines find a similar number of issues for complex metrics."""
        # Use a sample with multiple issues
        complex_metrics_file = None
        for file in self.metrics_files:
            if "complex" in file.name:
                complex_metrics_file = file
                break

        if not complex_metrics_file:
            self.skipTest("No complex metrics sample found")

        with open(complex_metrics_file, "r") as f:
            metrics = json.load(f)

        # Ensure metrics contains all required keys in the expected format
        complete_metrics = self._get_complete_test_metrics()
        for key in complete_metrics:
            if key not in metrics:
                metrics[key] = complete_metrics[key]

        # Force evaluation with both engines
        clips_result = evaluate(metrics, use_clips=True)
        legacy_result = evaluate(metrics, use_clips=False)

        clips_finding_count = len(clips_result.get("findings", []))
        legacy_finding_count = len(legacy_result.get("findings", []))

        # Allow some variation in number of findings
        self.assertLess(
            abs(clips_finding_count - legacy_finding_count),
            max(
                3, clips_finding_count * 0.2
            ),  # Allow 20% difference or up to 3 findings
            f"Finding count differs too much: CLIPS={clips_finding_count}, Legacy={legacy_finding_count}",
        )

    def test_critical_finding_consistency(self):
        """Test that both engines identify the same critical security issues."""
        critical_issues = [
            "patch_status",
            "firewall_all_disabled",
            "antivirus_not_detected",
        ]
        for metrics_file in self.metrics_files:
            metrics = self._load_and_complete_metrics(metrics_file)
            clips_result = evaluate(metrics, use_clips=True)
            legacy_result = evaluate(metrics, use_clips=False)
            clips_set = self._extract_critical_rules(clips_result)
            legacy_set = self._extract_critical_rules(legacy_result)
            for issue in critical_issues:
                self._check_critical_consistency(issue, clips_set, legacy_set)


@unittest.skipIf(not CLIPS_AVAILABLE, "CLIPS is required for these tests")
class TestCLIPSRulesDirect(unittest.TestCase):
    """Test CLIPS rules by directly loading them into the expert system."""

    def setUp(self):
        """Set up test environment with mocked CLIPS engine."""
        # Mock the clips module and environment
        self.clips_patcher = patch("src.clips_evaluator.clips")
        self.mock_clips = self.clips_patcher.start()

        # Create a mock environment with all required methods
        self.mock_env = Mock()
        self.mock_env.build = Mock()
        self.mock_env.load = Mock()
        self.mock_env.reset = Mock()
        self.mock_env.run = Mock()
        self.mock_env.eval = Mock()
        self.mock_env.assert_string = Mock()

        # Make facts() return an empty list so it's iterable
        self.mock_env.facts = Mock(return_value=[])

        # Make the clips.Environment return our mock environment
        self.mock_clips.Environment.return_value = self.mock_env

        # Now create the expert system with our properly configured mock
        from src.clips_evaluator import SecurityExpertSystem

        self.expert_system = SecurityExpertSystem()

        # Mock key methods to avoid deep calls into CLIPS
        self.expert_system.convert_metrics_to_facts = Mock()
        self.expert_system.run_evaluation = Mock(return_value=1)
        self.expert_system.get_findings = Mock(
            return_value=[
                {
                    "rule": "test_rule",
                    "level": "info",
                    "description": "Test finding",
                    "score_impact": {"type": "neutral", "value": 0},
                }
            ]
        )
        self.expert_system.get_score = Mock(return_value=85)
        self.expert_system.get_rule_trace = Mock(return_value=[])

    def tearDown(self):
        """Clean up after tests."""
        self.clips_patcher.stop()

    def test_patch_rules(self):
        """Test CLIPS rules for patch status evaluation."""
        # Include 'patch' key in metrics
        metrics = {
            "patch": {
                "status": "out-of-date",
                "last_update": "2023-01-01",
            },
            # Add other necessary keys
            "antivirus": {"products": []},
            "firewall": {"profiles": {}},
            "password_policy": {},
            "ports": [],
            "services": [],
        }

        result = self.expert_system.evaluate(metrics)
        self.assertIsNotNone(result)

        # Verify convert_metrics_to_facts was called with the metrics
        self.expert_system.convert_metrics_to_facts.assert_called_once_with(metrics)

        # Since we're mocking the findings, just check the result has expected structure
        self.assertIn("score", result)
        self.assertIn("grade", result)
        self.assertIn("findings", result)

    def test_firewall_rules(self):
        """Test CLIPS rules for firewall status evaluation."""
        metrics = {
            "firewall": {
                "profiles": {
                    "Domain": "OFF",
                    "Private": "ON",
                    "Public": "ON",
                }
            },
            # Add other necessary keys
            "patch": {"status": "up-to-date"},
            "antivirus": {"products": []},
            "password_policy": {},
            "ports": [],
            "services": [],
        }

        result = self.expert_system.evaluate(metrics)
        self.assertIsNotNone(result)

        # Verify convert_metrics_to_facts was called with the metrics
        self.expert_system.convert_metrics_to_facts.assert_called_once_with(metrics)

        # Since we're mocking the findings, just check the result has expected structure
        self.assertIn("score", result)
        self.assertIn("grade", result)
        self.assertIn("findings", result)

    def test_antivirus_rules(self):
        """Test CLIPS rules for antivirus status evaluation."""
        metrics = {
            "antivirus": {
                "products": [{"name": "Test AV", "state": "ON", "up_to_date": True}]
            },
            # Add other necessary keys
            "patch": {"status": "up-to-date"},
            "firewall": {"profiles": {}},
            "password_policy": {},
            "ports": [],
            "services": [],
        }

        result = self.expert_system.evaluate(metrics)
        self.assertIsNotNone(result)

        # Verify convert_metrics_to_facts was called with the metrics
        self.expert_system.convert_metrics_to_facts.assert_called_once_with(metrics)

        # Since we're mocking the findings, just check the result has expected structure
        self.assertIn("score", result)
        self.assertIn("grade", result)
        self.assertIn("findings", result)

    def test_password_policy_rules(self):
        """Test CLIPS rules for password policy evaluation."""
        metrics = {
            "password_policy": {
                "min_length": 8,
                "complexity": "enabled",
                "history_size": 5,
                "max_age": 90,
                "lockout_threshold": 5,
            },
            # Add other necessary keys
            "patch": {"status": "up-to-date"},
            "antivirus": {"products": []},
            "firewall": {"profiles": {}},
            "ports": [],
            "services": [],
        }

        result = self.expert_system.evaluate(metrics)
        self.assertIsNotNone(result)

        # Verify convert_metrics_to_facts was called with the metrics
        self.expert_system.convert_metrics_to_facts.assert_called_once_with(metrics)

        # Since we're mocking the findings, just check the result has expected structure
        self.assertIn("score", result)
        self.assertIn("grade", result)
        self.assertIn("findings", result)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
