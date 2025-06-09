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
    """Tests for the CLIPS-based evaluation function."""

    def setUp(self):
        self.metrics = {"key": "value"}

    def test_evaluate_clips_success(self):
        """Test successful CLIPS evaluation with expert system."""
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
        """Test fallback to legacy evaluation when CLIPS module import fails."""
        fake_module = types.ModuleType("src.clips_evaluator")
        with patch.dict(sys.modules, {"src.clips_evaluator": fake_module}):
            with patch("src.rules._evaluate_legacy") as mock_legacy:
                mock_legacy.return_value = {"fallback": True}
                result = _evaluate_clips(self.metrics)
                mock_legacy.assert_called_once_with(self.metrics)
                self.assertEqual(result, {"fallback": True})

    def test_evaluate_clips_exception_in_evaluate_fallback(self):
        """Test fallback to legacy evaluation when CLIPS expert system raises an exception."""
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
    """Tests for the main evaluate wrapper function."""

    @patch("src.rules._evaluate_legacy")
    def test_standard_evaluation_output(self, mock_legacy):
        """Test that evaluate returns correctly structured output."""
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
        """Test that CLIPS-based evaluation returns correctly structured output."""
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
    """Tests for the score calculation function."""

    def test_penalty_application_and_defaults(self):
        """Test score penalties are correctly applied for different finding levels."""
        findings = [
            {"level": "critical"},
            {"level": "warning"},
            {"level": "info"},
            {"level": "unknown"},
        ]
        score = calculate_score(findings, base_score=100)
        self.assertEqual(score, 50)

    def test_clamping_below_zero(self):
        """Test that score cannot go below zero even with many critical findings."""
        findings = [{"level": "critical"}] * 5
        self.assertEqual(calculate_score(findings), 0)

    def test_no_findings_stays_at_base(self):
        """Test that score remains at base value when no findings exist."""
        self.assertEqual(calculate_score([], base_score=100), 100)


class TestEvaluateLegacyRules(unittest.TestCase):
    """Tests for the legacy rule evaluation system."""

    def test_patch_status_rule_fired(self):
        """Test that patch_status rule triggers for out-of-date systems."""
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
        """Test that open_ports rule triggers when ports are detected."""
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
        """Test that service_count rule triggers when many services are running."""
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
        """Test grade assignment and summary generation with multiple findings."""
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
        """Test 'Good' grade assignment with only warning and info findings."""
        metrics = {
            "patch": {"status": "up-to-date", "hotfixes": []},
            "ports": {"ports": [22]},
            "services": {"services": [None] * (SERVICE_COUNT_THRESHOLD + 1)},
        }
        result = _evaluate_legacy(metrics)
        self.assertEqual(result["grade"], "Good")

    def test_critical_risk_grade_assignment(self):
        """Test 'Critical Risk' grade assignment with critical findings."""
        metrics = {
            "patch": {"status": "out-of-date", "hotfixes": []},
            "ports": {"ports": [22]},
            "services": {"services": [None] * (SERVICE_COUNT_THRESHOLD + 1)},
        }
        result = _evaluate_legacy(metrics)
        self.assertEqual(result["grade"], "Critical Risk")

    def test_fair_grade_threshold(self):
        """Test 'Fair' grade assignment for scores between 60-79."""
        metrics = {
            "patch": {"status": "up-to-date", "hotfixes": []},
            "ports": {"ports": []},
            "services": {"services": []},
        }
        with patch("src.rules.calculate_score", return_value=70):
            result = _evaluate_legacy(metrics)
            self.assertEqual(result["grade"], "Fair")

    def test_poor_grade_threshold(self):
        """Test 'Poor' grade assignment for scores between 40-59."""
        metrics = {
            "patch": {"status": "up-to-date", "hotfixes": []},
            "ports": {"ports": []},
            "services": {"services": []},
        }
        with patch("src.rules.calculate_score", return_value=50):
            result = _evaluate_legacy(metrics)
            self.assertEqual(result["grade"], "Poor")

    def test_default_critical_risk_threshold(self):
        """Test 'Critical Risk' grade assignment for scores below 40."""
        metrics = {
            "patch": {"status": "up-to-date", "hotfixes": []},
            "ports": {"ports": []},
            "services": {"services": []},
        }
        with patch("src.rules.calculate_score", return_value=30):
            result = _evaluate_legacy(metrics)
            self.assertEqual(result["grade"], "Critical Risk")

    def test_firewall_all_disabled(self):
        """Test detection of completely disabled firewall."""
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
        """Test detection of partially disabled firewall (only public profile)."""
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
        """Test detection of fully enabled firewall."""
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
        """Test detection of missing antivirus software."""
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
        """Test detection of antivirus with unknown state."""
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

    def test_firewall_domain_disabled(self):
        """Test detection of disabled domain firewall profile."""
        metrics = {
            "patch": {"status": "up-to-date", "hotfixes": []},
            "ports": {"ports": []},
            "services": {"services": []},
            "firewall": {
                "profiles": {"domain": "OFF", "private": "ON", "public": "ON"}
            },
        }
        result = _evaluate_legacy(metrics)
        self.assertTrue(
            any(
                f["rule"] == "firewall_domain_disabled" and f["level"] == "warning"
                for f in result["findings"]
            )
        )

    def test_firewall_private_disabled(self):
        """Test detection of disabled private firewall profile."""
        metrics = {
            "patch": {"status": "up-to-date", "hotfixes": []},
            "ports": {"ports": []},
            "services": {"services": []},
            "firewall": {
                "profiles": {"domain": "ON", "private": "OFF", "public": "ON"}
            },
        }
        result = _evaluate_legacy(metrics)
        self.assertTrue(
            any(
                f["rule"] == "firewall_private_disabled" and f["level"] == "warning"
                for f in result["findings"]
            )
        )


class TestEvaluateWrapper(unittest.TestCase):
    """Tests for the evaluate wrapper function with auto-detection features."""

    @patch("src.rules._evaluate_legacy")
    def test_auto_detect_falls_back_to_legacy_and_injects_metadata(self, mock_legacy):
        """Test auto-detection falls back to legacy and adds timestamp metadata."""
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
        # Allow timestamp to be within a small window of time around the evaluation
        self.assertTrue(before - 0.1 <= ts.timestamp() <= after + 0.1)

    @patch("src.rules._evaluate_legacy")
    @patch("src.rules.logger")
    def test_clips_requested_not_available_falls_back_and_warns(
        self, mock_logger, mock_legacy
    ):
        """Test warning when CLIPS is requested but not available."""
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
