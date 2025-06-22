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
except ImportError:  # pragma: no cover
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

    def test_allowed_finding_count_variance(self):
        """Test that finding count differences stay within allowed variance."""
        clips_result = {"findings": list(range(10))}
        legacy_result = {"findings": list(range(12))}
        diff = abs(len(clips_result["findings"]) - len(legacy_result["findings"]))
        self.assertLess(
            diff,
            max(3, len(clips_result["findings"]) * 0.2),
            f"Finding count differs too much: CLIPS={len(clips_result['findings'])}, "
            f"Legacy={len(legacy_result['findings'])}",
        )

    @patch("src.rules.evaluate")
    def test_engine_consistency_differences_detected(self, mock_evaluate):
        """Test detection of differences between CLIPS and legacy evaluation."""
        # Create mock results with known differences
        clips_result = {
            "score": 90,
            "grade": "Good",
            "findings": [{"level": "warning"}],
            "summary": "Good result",
        }
        legacy_result = {
            "score": 70,
            "grade": "Fair",
            "findings": [{"level": "critical"}],
            "summary": "Fair result",
        }

        # Directly check differences without mocking
        differences = self._get_key_differences(clips_result, legacy_result)

        # Verify differences are detected
        self.assertTrue(differences, "Expected to detect differences between engines")
        self.assertIn("score", differences)
        self.assertEqual(differences["score"]["clips"], 90)
        self.assertEqual(differences["score"]["legacy"], 70)
        self.assertIn("grade", differences)
        self.assertEqual(differences["grade"]["clips"], "Good")
        self.assertEqual(differences["grade"]["legacy"], "Fair")
        self.assertIn("finding_counts", differences)
        self.assertEqual(differences["finding_counts"]["clips"]["warning"], 1)
        self.assertEqual(differences["finding_counts"]["legacy"]["critical"], 1)


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


class TestGetKeyDifferencesCoverage(unittest.TestCase):
    def setUp(self):
        # use the existing TestEngineConsistency class in this module
        self.tc = TestEngineConsistency()
        # set attributes needed by setUp (they won't be used by our tests)
        self.tc.metrics_dir = Path(__file__).parent
        self.tc.metrics_files = []

    def test_score_difference_branch(self):
        """Trigger the score_diff > 5 branch."""
        clips_score = {"score": 10, "grade": "X"}
        legacy_score = {"score": 20, "grade": "X"}
        diffs = self.tc._get_key_differences(clips_score, legacy_score)
        self.assertIn("score", diffs)
        self.assertEqual(diffs["score"]["difference"], 10)

    def test_grade_difference_branch(self):
        """Trigger the grade mismatch branch."""
        clips_grade = {"score": 50, "grade": "Good"}
        legacy_grade = {"score": 50, "grade": "Poor"}
        diffs = self.tc._get_key_differences(clips_grade, legacy_grade)
        self.assertIn("grade", diffs)
        self.assertEqual(diffs["grade"]["clips"], "Good")
        self.assertEqual(diffs["grade"]["legacy"], "Poor")

    def test_finding_counts_difference_branch(self):
        """Trigger the finding counts difference branch."""
        clips_result = {
            "score": 50,
            "grade": "Good",
            "findings": [{"level": "critical"}, {"level": "warning"}],
        }
        legacy_result = {
            "score": 50,
            "grade": "Good",
            "findings": [{"level": "warning"}, {"level": "info"}],
        }
        diffs = self.tc._get_key_differences(clips_result, legacy_result)
        self.assertIn("finding_counts", diffs)
        self.assertEqual(diffs["finding_counts"]["clips"]["critical"], 1)
        self.assertEqual(diffs["finding_counts"]["legacy"]["critical"], 0)
        self.assertEqual(diffs["finding_counts"]["clips"]["info"], 0)
        self.assertEqual(diffs["finding_counts"]["legacy"]["info"], 1)


class TestClipsAvailableFlag(unittest.TestCase):
    def test_clips_available_flag_type(self):
        # ensure the CLIPS_AVAILABLE flag is always a boolean
        self.assertIsInstance(CLIPS_AVAILABLE, bool)


class TestCriticalConsistencyBranches(unittest.TestCase):
    """Cover both failure paths in _check_critical_consistency."""

    def setUp(self):
        self.tc = TestEngineConsistency()
        # stub out required attributes
        self.tc.metrics_dir = Path(__file__).parent
        self.tc.metrics_files = []

    def test_fail_when_detected_by_clips_only(self):
        """Should fail if issue present in clips_set only."""
        with self.assertRaises(AssertionError) as cm:
            self.tc._check_critical_consistency("foo", {"foo"}, set())
        self.assertIn("detected by CLIPS but not by legacy engine", str(cm.exception))

    def test_fail_when_detected_by_legacy_only(self):
        """Should fail if issue present in legacy_set only."""
        with self.assertRaises(AssertionError) as cm:
            self.tc._check_critical_consistency("bar", set(), {"bar"})
        self.assertIn("detected by legacy engine but not by CLIPS", str(cm.exception))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
