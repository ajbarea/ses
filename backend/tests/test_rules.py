import unittest
from unittest.mock import patch
import types
import sys
import time
from datetime import datetime

from src import rules
from src.rules import (
    _evaluate_clips,
    _evaluate_legacy,
    evaluate,
    CLIPS_AVAILABLE,
    calculate_score,
    SERVICE_COUNT_THRESHOLD,
    RULE_DESCRIPTIONS,
)


class TestEvaluateClips(unittest.TestCase):
    """Unit tests for _evaluate_clips function."""

    def setUp(self):
        self.metrics = {"key": "value"}

    def test_evaluate_clips_success(self):
        """Verify CLIPS evaluation success scenario."""
        fake_result = {"score": 75, "findings": []}
        fake_module = types.ModuleType("src.clips_evaluator")

        class FakeExpert:
            def evaluate(self, metrics):
                return fake_result

        fake_module.SecurityExpertSystem = FakeExpert
        with patch.dict(sys.modules, {"src.clips_evaluator": fake_module}):
            result = _evaluate_clips(self.metrics)
            self.assertIs(result, fake_result)

    def test_evaluate_clips_import_error_fallback(self):
        """Check fallback when CLIPS import fails."""
        fake_module = types.ModuleType("src.clips_evaluator")
        with patch.dict(sys.modules, {"src.clips_evaluator": fake_module}):
            with patch("src.rules._evaluate_legacy") as mock_legacy:
                mock_legacy.return_value = {"fallback": True}
                result = _evaluate_clips(self.metrics)
                mock_legacy.assert_called_once_with(self.metrics)
                self.assertEqual(result, {"fallback": True})

    def test_evaluate_clips_exception_in_evaluate_fallback(self):
        """Check fallback when CLIPS evaluation raises errors."""
        fake_module = types.ModuleType("src.clips_evaluator")

        class BadExpert:
            def evaluate(self, metrics):
                raise RuntimeError("evaluation error")

        fake_module.SecurityExpertSystem = BadExpert
        with patch.dict(sys.modules, {"src.clips_evaluator": fake_module}):
            with patch("src.rules._evaluate_legacy") as mock_legacy:
                mock_legacy.return_value = {"fallback2": True}
                result = _evaluate_clips(self.metrics)
                mock_legacy.assert_called_once_with(self.metrics)
                self.assertEqual(result, {"fallback2": True})


class TestEvaluation(unittest.TestCase):
    """Unit tests for the evaluate wrapper."""

    @patch("src.rules._evaluate_legacy")
    def test_standard_evaluation_output(self, mock_legacy):
        """Check overall structure of evaluation output."""
        dummy = {"x": 1}
        mock_legacy.return_value = {
            "score": 100,
            "grade": "Excellent",
            "summary": "",
            "findings": [],
        }
        result = evaluate(dummy, use_clips=False)
        self.assertIn("score", result)
        self.assertIn("grade", result)
        self.assertIn("summary", result)
        self.assertIsInstance(result["score"], (int, float))
        self.assertIsInstance(result.get("findings"), list)
        mock_legacy.assert_called_once_with(dummy)

    @unittest.skipIf(
        not CLIPS_AVAILABLE, "Skipping CLIPS tests: PyCLIPS package required"
    )
    @patch("src.rules._evaluate_clips")
    def test_clips_evaluation_output(self, mock_clips):
        DUMMY_METRICS = {"patch": {"hotfixes": ["KB1"], "status": "up-to-date"}}
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


class TestCalculateScore(unittest.TestCase):
    def test_penalty_application_and_defaults(self):
        """Check penalty application and default severity deduction."""
        findings = [
            {"level": "critical"},
            {"level": "warning"},
            {"level": "info"},
            {"level": "unknown"},
        ]
        score = calculate_score(findings, base_score=100)
        self.assertEqual(score, 50)

    def test_clamping_below_zero(self):
        """Ensure score does not drop below 0."""
        findings = [{"level": "critical"}] * 5
        self.assertEqual(calculate_score(findings), 0)

    def test_no_findings_stays_at_base(self):
        """Verify score remains at base if no findings."""
        self.assertEqual(calculate_score([], base_score=100), 100)


class TestEvaluateLegacyRules(unittest.TestCase):
    def test_patch_status_rule_fired(self):
        """Check 'patch_status' rule triggers appropriately."""
        metrics = {
            "patch": {"status": "out-of-date", "hotfixes": []},
            "ports": {"ports": []},
            "services": {"services": []},
        }
        result = _evaluate_legacy(metrics)
        self.assertTrue(
            any(
                f["rule"] == "patch_status" and f["level"] == "critical"
                for f in result["findings"]
            )
        )
        self.assertEqual(
            result["summary"], RULE_DESCRIPTIONS["patch_status"]["description"]
        )

    def test_open_ports_rule_fired(self):
        """Check 'open_ports' rule triggers when open ports exist."""
        metrics = {
            "patch": {"status": "up-to-date", "hotfixes": ["KB"]},
            "ports": {"ports": [22, 80]},
            "services": {"services": []},
        }
        result = _evaluate_legacy(metrics)
        self.assertTrue(
            any(
                f["rule"] == "open_ports" and f["level"] == "warning"
                for f in result["findings"]
            )
        )
        details = next(f for f in result["findings"] if f["rule"] == "open_ports")[
            "details"
        ]
        self.assertIn(22, details)

    def test_service_count_rule_fired(self):
        """Check 'service_count' rule triggers above threshold."""
        metrics = {
            "patch": {"status": "up-to-date", "hotfixes": ["KB"]},
            "ports": {"ports": []},
            "services": {"services": [None] * (SERVICE_COUNT_THRESHOLD + 1)},
        }
        result = _evaluate_legacy(metrics)
        self.assertTrue(
            any(
                f["rule"] == "service_count" and f["level"] == "info"
                for f in result["findings"]
            )
        )

    def test_grade_boundaries_and_summary(self):
        """Check correct grade assignment and summary generation."""
        metrics = {
            "patch": {"status": "out-of-date", "hotfixes": []},
            "ports": {"ports": [1]},
            "services": {"services": [None] * (SERVICE_COUNT_THRESHOLD + 1)},
        }
        result = _evaluate_legacy(metrics)
        self.assertEqual(result["grade"], "Critical Risk")
        self.assertIn(";", result["summary"])
        for f in result["findings"]:
            self.assertIn(
                f["description"], [d["description"] for d in RULE_DESCRIPTIONS.values()]
            )

    def test_good_grade_assignment(self):
        """Check 'Good' grade assignment when only warning and info findings exist."""
        metrics = {
            "patch": {"status": "up-to-date", "hotfixes": []},
            "ports": {"ports": [22]},
            "services": {"services": [None] * (SERVICE_COUNT_THRESHOLD + 1)},
        }
        result = _evaluate_legacy(metrics)
        self.assertEqual(result["grade"], "Good")

    def test_critical_risk_grade_assignment(self):
        """Check 'Critical Risk' grade assignment when all findings present."""
        metrics = {
            "patch": {"status": "out-of-date", "hotfixes": []},
            "ports": {"ports": [22]},
            "services": {"services": [None] * (SERVICE_COUNT_THRESHOLD + 1)},
        }
        result = _evaluate_legacy(metrics)
        self.assertEqual(result["grade"], "Critical Risk")

    def test_fair_grade_threshold(self):
        """Check 'Fair' grade when score is between 60 and 79 with no critical findings."""
        metrics = {
            "patch": {"status": "up-to-date", "hotfixes": []},
            "ports": {"ports": []},
            "services": {"services": []},
        }
        with patch("src.rules.calculate_score", return_value=70):
            result = _evaluate_legacy(metrics)
            self.assertEqual(result["grade"], "Fair")

    def test_poor_grade_threshold(self):
        """Check 'Poor' grade when score is between 40 and 59 with no critical findings."""
        metrics = {
            "patch": {"status": "up-to-date", "hotfixes": []},
            "ports": {"ports": []},
            "services": {"services": []},
        }
        with patch("src.rules.calculate_score", return_value=50):
            result = _evaluate_legacy(metrics)
            self.assertEqual(result["grade"], "Poor")

    def test_default_critical_risk_threshold(self):
        """Check 'Critical Risk' grade when score is below 40 with no critical findings."""
        metrics = {
            "patch": {"status": "up-to-date", "hotfixes": []},
            "ports": {"ports": []},
            "services": {"services": []},
        }
        with patch("src.rules.calculate_score", return_value=30):
            result = _evaluate_legacy(metrics)
            self.assertEqual(result["grade"], "Critical Risk")

    def test_firewall_all_disabled(self):
        metrics = {
            "patch": {"status": "up-to-date", "hotfixes": []},
            "ports": {"ports": []},
            "services": {"services": []},
            "firewall": {
                "profiles": {"domain": "OFF", "private": "OFF", "public": "OFF"}
            },
        }
        result = _evaluate_legacy(metrics)
        self.assertTrue(
            any(
                f["rule"] == "firewall_all_disabled" and f["level"] == "critical"
                for f in result["findings"]
            )
        )

    def test_firewall_partial_disabled(self):
        metrics = {
            "patch": {"status": "up-to-date", "hotfixes": []},
            "ports": {"ports": []},
            "services": {"services": []},
            "firewall": {
                "profiles": {"domain": "ON", "private": "ON", "public": "OFF"}
            },
        }
        result = _evaluate_legacy(metrics)
        self.assertTrue(
            any(
                f["rule"] == "firewall_public_disabled" and f["level"] == "warning"
                for f in result["findings"]
            )
        )

    def test_firewall_all_enabled(self):
        metrics = {
            "patch": {"status": "up-to-date", "hotfixes": []},
            "ports": {"ports": []},
            "services": {"services": []},
            "firewall": {"profiles": {"domain": "ON", "private": "ON", "public": "ON"}},
        }
        result = _evaluate_legacy(metrics)
        self.assertTrue(
            any(
                f["rule"] == "firewall_all_enabled" and f["level"] == "info"
                for f in result["findings"]
            )
        )

    def test_antivirus_not_detected(self):
        metrics = {
            "patch": {"status": "up-to-date", "hotfixes": []},
            "ports": {"ports": []},
            "services": {"services": []},
            "antivirus": {"products": []},
        }
        result = _evaluate_legacy(metrics)
        self.assertTrue(
            any(
                f["rule"] == "antivirus_not_detected" and f["level"] == "critical"
                for f in result["findings"]
            )
        )

    def test_antivirus_state_unknown(self):
        metrics = {
            "patch": {"status": "up-to-date", "hotfixes": []},
            "ports": {"ports": []},
            "services": {"services": []},
            "antivirus": {"products": [{"name": "Defender", "state": None}]},
        }
        result = _evaluate_legacy(metrics)
        self.assertTrue(
            any(
                f["rule"] == "antivirus_Defender_unknown" and f["level"] == "warning"
                for f in result["findings"]
            )
        )


class TestEvaluateWrapper(unittest.TestCase):
    @patch("src.rules._evaluate_legacy")
    def test_auto_detect_falls_back_to_legacy_and_injects_metadata(self, mock_legacy):
        """Check fallback to legacy engine and metadata injection."""
        dummy = {"x": 1}
        mock_legacy.return_value = {
            "score": 80,
            "grade": "Good",
            "findings": [],
            "summary": "",
        }
        with patch.object(rules, "CLIPS_AVAILABLE", False):
            before = time.time()
            result = evaluate(dummy, use_clips=None)
            after = time.time()
        mock_legacy.assert_called_once_with(dummy)
        self.assertIn("timestamp", result)
        ts = datetime.fromisoformat(result["timestamp"])
        # Allow ts.timestamp() to be slightly before 'before' or slightly after 'after'
        # to account for system-specific timing variations.
        self.assertTrue(before - 0.1 <= ts.timestamp() <= after + 0.1)

    @patch("src.rules._evaluate_legacy")
    @patch("src.rules.logger")
    def test_clips_requested_not_available_falls_back_and_warns(
        self, mock_logger, mock_legacy
    ):
        """Check fallback to legacy and warning when use_clips=True but CLIPS is not available."""
        dummy = {"x": 1}
        mock_legacy.return_value = {
            "score": 80,
            "grade": "Good",
            "findings": [],
            "summary": "",
        }
        with patch.object(rules, "CLIPS_AVAILABLE", False):
            evaluate(dummy, use_clips=True)

        mock_legacy.assert_called_once_with(dummy)
        mock_logger.warning.assert_called_once_with(
            "CLIPS evaluation requested but CLIPS is not available. Falling back to legacy."
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
