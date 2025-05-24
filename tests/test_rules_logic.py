import unittest
from unittest.mock import patch
from datetime import datetime
import time

import rules
from rules import (
    calculate_score,
    _evaluate_legacy,
    evaluate,
    SERVICE_COUNT_THRESHOLD,
    RULE_DESCRIPTIONS,
)


class TestCalculateScore(unittest.TestCase):
    def test_penalty_application_and_defaults(self):
        findings = [
            {"level": "critical"},
            {"level": "warning"},
            {"level": "info"},
            {"level": "unknown"},
        ]
        # critical=-30, warning=-10, info=-5, unknown defaults to -5 → total -50 → score 50
        score = calculate_score(findings, base_score=100)
        self.assertEqual(score, 50)

    def test_clamping_below_zero(self):
        findings = [{"level": "critical"}] * 5  # -150 → clamped to 0
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
        # penalties: -30 -10 -5 = -45 → score 55 → Poor
        self.assertEqual(result["grade"], "Poor")
        # summary should be joined descriptions
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
        # force CLIPS unavailable
        with patch.object(rules, "CLIPS_AVAILABLE", False):
            before = time.time()
            result = evaluate(dummy, use_clips=None)
            after = time.time()

        mock_legacy.assert_called_once_with(dummy)
        self.assertIn("timestamp", result)
        # timestamp should be around now
        ts = datetime.fromisoformat(result["timestamp"])
        self.assertTrue(before <= ts.replace(tzinfo=None).timestamp() <= after)
        self.assertEqual(result["metrics"], dummy)


if __name__ == "__main__":
    unittest.main()
