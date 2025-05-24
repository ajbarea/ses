import unittest
from unittest.mock import patch
import types
import sys
import time
from datetime import datetime

import rules
from rules import (
    _evaluate_clips,
    _evaluate_legacy,
    evaluate,
    CLIPS_AVAILABLE,
    calculate_score,
    SERVICE_COUNT_THRESHOLD,
    RULE_DESCRIPTIONS,
)


class TestEvaluateClips(unittest.TestCase):
    """Unit tests for the _evaluate_clips function in rules.py."""

    def setUp(self):
        self.metrics = {"key": "value"}

    def test_evaluate_clips_success(self):
        fake_result = {"score": 75, "findings": []}
        fake_module = types.ModuleType("clips_evaluator")

        class FakeExpert:
            def evaluate(self, metrics):
                return fake_result

        fake_module.SecurityExpertSystem = FakeExpert
        with patch.dict(sys.modules, {"clips_evaluator": fake_module}):
            result = _evaluate_clips(self.metrics)
            self.assertIs(result, fake_result)

    def test_evaluate_clips_import_error_fallback(self):
        fake_module = types.ModuleType("clips_evaluator")
        with patch.dict(sys.modules, {"clips_evaluator": fake_module}):
            with patch("rules._evaluate_legacy") as mock_legacy:
                mock_legacy.return_value = {"fallback": True}
                result = _evaluate_clips(self.metrics)
                mock_legacy.assert_called_once_with(self.metrics)
                self.assertEqual(result, {"fallback": True})

    def test_evaluate_clips_exception_in_evaluate_fallback(self):
        fake_module = types.ModuleType("clips_evaluator")

        class BadExpert:
            def evaluate(self, metrics):
                raise RuntimeError("evaluation error")

        fake_module.SecurityExpertSystem = BadExpert
        with patch.dict(sys.modules, {"clips_evaluator": fake_module}):
            with patch("rules._evaluate_legacy") as mock_legacy:
                mock_legacy.return_value = {"fallback2": True}
                result = _evaluate_clips(self.metrics)
                mock_legacy.assert_called_once_with(self.metrics)
                self.assertEqual(result, {"fallback2": True})


class TestEvaluation(unittest.TestCase):
    """Unit tests for evaluate wrapper in rules.py."""

    @patch("rules._evaluate_legacy")
    def test_standard_evaluation_output(self, mock_legacy):
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
    @patch("rules._evaluate_clips")
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
        findings = [
            {"level": "critical"},
            {"level": "warning"},
            {"level": "info"},
            {"level": "unknown"},
        ]
        score = calculate_score(findings, base_score=100)
        self.assertEqual(score, 50)

    def test_clamping_below_zero(self):
        findings = [{"level": "critical"}] * 5
        self.assertEqual(calculate_score(findings), 0)

    def test_no_findings_stays_at_base(self):
        self.assertEqual(calculate_score([], base_score=100), 100)


class TestEvaluateLegacyRules(unittest.TestCase):
    def test_patch_status_rule_fired(self):
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
        metrics = {
            "patch": {"status": "out-of-date", "hotfixes": []},
            "ports": {"ports": [1]},
            "services": {"services": [None] * (SERVICE_COUNT_THRESHOLD + 1)},
        }
        result = _evaluate_legacy(metrics)
        self.assertEqual(result["grade"], "Poor")
        self.assertIn(";", result["summary"])
        for f in result["findings"]:
            self.assertIn(
                f["description"], [d["description"] for d in RULE_DESCRIPTIONS.values()]
            )


class TestEvaluateWrapper(unittest.TestCase):
    @patch("rules._evaluate_legacy")
    def test_auto_detect_falls_back_to_legacy_and_injects_metadata(self, mock_legacy):
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
        self.assertTrue(before <= ts.replace(tzinfo=None).timestamp() <= after)
        self.assertEqual(result["metrics"], dummy)


if __name__ == "__main__":
    unittest.main()
