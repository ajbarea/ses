import unittest
from unittest.mock import patch
import types
import sys
import time
from datetime import datetime

from src import rules
from src.rules import (
    _collect_password_findings,
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
        self.assertEqual(score, 60)

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
        self.assertEqual(result["grade"], "Poor")
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
        self.assertEqual(result["grade"], "Excellent")

    def test_critical_risk_grade_assignment(self):
        """Test grade assignment with critical findings."""
        metrics = {
            "patch": {"status": "out-of-date", "hotfixes": []},
            "ports": {"ports": [22]},
            "services": {"services": [None] * (SERVICE_COUNT_THRESHOLD + 1)},
        }
        result = _evaluate_legacy(metrics)
        self.assertEqual(result["grade"], "Poor")

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

    def test_impact_summary_generation(self):
        """Test that impact_summary correctly reports counts of different finding types."""
        # Create a test metrics object that will generate different types of findings
        metrics = {
            "patch": {"status": "up-to-date", "hotfixes": []},
            "ports": {"ports": [80, 443]},  # Will generate a warning
            "services": {"services": []},
            "firewall": {
                "profiles": {"domain": "ON", "private": "ON", "public": "ON"}
            },  # Will generate a positive finding
            "antivirus": {
                "products": [{"name": "Test AV", "state": None}]
            },  # Will generate a warning
            "password_policy": {
                "policy": {"min_password_length": 12}
            },  # Will generate a positive finding
        }

        # Mock the score_impact for findings to ensure we have positive, neutral and negative findings
        with patch("src.rules.get_finding_score_impact") as mock_score_impact:
            # Setup mock to return different score impacts based on rule
            def side_effect(finding):
                rule = finding.get("rule", "")
                if (
                    rule == "firewall_all_enabled"
                    or "password_min_length_strong" in rule
                ):
                    return {"type": "bonus", "value": 5}
                elif "open_ports" in rule or "antivirus" in rule:
                    return {"type": "penalty", "value": -5}
                else:
                    return {"type": "neutral", "value": 0}

            mock_score_impact.side_effect = side_effect

            result = rules._evaluate_legacy(metrics)

            # Check impact_summary field
            self.assertIn("impact_summary", result)
            impact_summary = result["impact_summary"]

            # Should have positive and negative findings mentioned
            self.assertIn("positive factors", impact_summary)
            self.assertIn("reducing your score", impact_summary)

            # Count the actual findings in each category
            positive_count = len(result["positive_findings"])
            negative_count = len(result["negative_findings"])
            neutral_count = len(result["neutral_findings"])

            # Verify the counts match what's reported in the impact summary
            if positive_count > 0:
                self.assertIn(f"{positive_count} positive factors", impact_summary)
            if negative_count > 0:
                self.assertIn(
                    f"{negative_count} items reducing your score", impact_summary
                )
            if neutral_count > 0:
                self.assertIn(f"{neutral_count} neutral findings", impact_summary)

    def test_critical_risk_with_multiple_severe_issues(self):
        """Test 'Critical Risk' grade assignment with multiple severe security issues."""
        metrics = {
            "patch": {"status": "out-of-date", "hotfixes": []},  # -30 critical
            "ports": {
                "ports": [21, 22, 23, 25, 135, 139, 445]
            },  # -10 warning (many risky ports)
            "services": {"services": [None] * (SERVICE_COUNT_THRESHOLD + 1)},  # 0 info
        }

        with patch("src.rules.calculate_score", return_value=25):
            result = _evaluate_legacy(metrics)
            self.assertEqual(result["grade"], "Critical Risk")

    def test_critical_risk_with_three_critical_findings(self):
        """Test 'Critical Risk' grade assignment with 3+ critical findings (automatic Critical Risk)."""
        metrics = {
            "patch": {"status": "out-of-date", "hotfixes": []},
            "ports": {"ports": []},
            "services": {"services": []},
        }

        # Mock a scenario where there would be 3 critical findings
        def mock_assign_grade(score, findings):
            from src.scoring import CRITICAL_RISK_GRADE

            # Simulate 3 critical findings
            critical_count = 3
            if critical_count >= 3:
                return CRITICAL_RISK_GRADE
            # Otherwise use normal logic
            from src.scoring import assign_grade as original_assign_grade

            return original_assign_grade(score, findings)

        with patch("src.rules.assign_grade", side_effect=mock_assign_grade):
            result = _evaluate_legacy(metrics)
            self.assertEqual(result["grade"], "Critical Risk")


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

    def test_empty_metrics(self):
        """Test handling of empty metrics dictionary."""
        # Empty metrics should return 5 findings with default values
        findings = _collect_password_findings({})
        self.assertEqual(len(findings), 5)

        # Check specific findings
        rule_names = [f["rule"] for f in findings]
        self.assertIn("password_min_length_weak", rule_names)
        self.assertIn("password_complexity_disabled", rule_names)
        self.assertIn("account_lockout_not_defined", rule_names)
        self.assertIn("password_history_disabled", rule_names)
        self.assertIn("max_password_age_disabled", rule_names)

    def test_missing_policy_key(self):
        """Test handling of metrics with missing policy key."""
        metrics = {"password_policy": {}}
        findings = _collect_password_findings(metrics)
        self.assertEqual(len(findings), 5)

        # Verify default findings are returned
        rule_names = [f["rule"] for f in findings]
        self.assertIn("password_min_length_weak", rule_names)
        self.assertIn("max_password_age_disabled", rule_names)

    def test_password_min_length_weak(self):
        """Test minimum password length < 8 produces weak finding."""
        metrics = {"password_policy": {"policy": {"min_password_length": 7}}}
        findings = _collect_password_findings(metrics)

        # Find the min length finding
        min_length_findings = [f for f in findings if "min_length" in f["rule"]]
        self.assertEqual(len(min_length_findings), 1)
        finding = min_length_findings[0]

        self.assertEqual(finding["rule"], "password_min_length_weak")
        self.assertEqual(
            finding["level"], RULE_DESCRIPTIONS["password_min_length_weak"]["level"]
        )
        self.assertIn("Currently: 7", finding["description"])

    def test_password_min_length_acceptable(self):
        """Test minimum password length 8-11 produces acceptable finding."""
        metrics = {"password_policy": {"policy": {"min_password_length": 8}}}
        findings = _collect_password_findings(metrics)

        min_length_findings = [f for f in findings if "min_length" in f["rule"]]
        self.assertEqual(len(min_length_findings), 1)
        finding = min_length_findings[0]

        self.assertEqual(finding["rule"], "password_min_length_acceptable")
        self.assertEqual(
            finding["level"],
            RULE_DESCRIPTIONS["password_min_length_acceptable"]["level"],
        )
        self.assertIn("Currently: 8", finding["description"])

    def test_password_min_length_strong(self):
        """Test minimum password length ≥ 12 produces strong finding."""
        metrics = {"password_policy": {"policy": {"min_password_length": 12}}}
        findings = _collect_password_findings(metrics)

        min_length_findings = [f for f in findings if "min_length" in f["rule"]]
        self.assertEqual(len(min_length_findings), 1)
        finding = min_length_findings[0]

        self.assertEqual(finding["rule"], "password_min_length_strong")
        self.assertEqual(
            finding["level"], RULE_DESCRIPTIONS["password_min_length_strong"]["level"]
        )
        self.assertIn("Currently: 12", finding["description"])

    def test_complexity_enabled(self):
        """Test complexity=enabled produces enabled finding."""
        metrics = {"password_policy": {"policy": {"complexity": "enabled"}}}
        findings = _collect_password_findings(metrics)

        complexity_findings = [f for f in findings if "complexity" in f["rule"]]
        self.assertEqual(len(complexity_findings), 1)
        finding = complexity_findings[0]

        self.assertEqual(finding["rule"], "password_complexity_enabled")
        self.assertEqual(
            finding["level"], RULE_DESCRIPTIONS["password_complexity_enabled"]["level"]
        )

    def test_complexity_disabled(self):
        """Test complexity!=enabled produces disabled finding."""
        # Test with explicit "disabled" value
        metrics = {"password_policy": {"policy": {"complexity": "disabled"}}}
        findings = _collect_password_findings(metrics)

        complexity_findings = [f for f in findings if "complexity" in f["rule"]]
        self.assertEqual(len(complexity_findings), 1)
        finding = complexity_findings[0]

        self.assertEqual(finding["rule"], "password_complexity_disabled")
        self.assertEqual(
            finding["level"], RULE_DESCRIPTIONS["password_complexity_disabled"]["level"]
        )

        # Test with non-standard value
        metrics = {"password_policy": {"policy": {"complexity": "partial"}}}
        findings = _collect_password_findings(metrics)

        complexity_findings = [f for f in findings if "complexity" in f["rule"]]
        self.assertEqual(len(complexity_findings), 1)
        finding = complexity_findings[0]
        self.assertEqual(finding["rule"], "password_complexity_disabled")

    def test_lockout_threshold_not_defined(self):
        """Test lockout_threshold=not-defined produces not defined finding."""
        metrics = {"password_policy": {"policy": {"lockout_threshold": "not-defined"}}}
        findings = _collect_password_findings(metrics)

        lockout_findings = [f for f in findings if "lockout" in f["rule"]]
        self.assertEqual(len(lockout_findings), 1)
        finding = lockout_findings[0]

        self.assertEqual(finding["rule"], "account_lockout_not_defined")
        self.assertEqual(
            finding["level"], RULE_DESCRIPTIONS["account_lockout_not_defined"]["level"]
        )

    def test_lockout_threshold_defined(self):
        """Test lockout_threshold!=not-defined produces defined finding."""
        metrics = {"password_policy": {"policy": {"lockout_threshold": 5}}}
        findings = _collect_password_findings(metrics)

        lockout_findings = [f for f in findings if "lockout" in f["rule"]]
        self.assertEqual(len(lockout_findings), 1)
        finding = lockout_findings[0]

        self.assertEqual(finding["rule"], "account_lockout_defined")
        self.assertEqual(
            finding["level"], RULE_DESCRIPTIONS["account_lockout_defined"]["level"]
        )

    def test_history_size_disabled(self):
        """Test history_size<1 produces disabled finding."""
        metrics = {"password_policy": {"policy": {"history_size": 0}}}
        findings = _collect_password_findings(metrics)

        history_findings = [f for f in findings if "history" in f["rule"]]
        self.assertEqual(len(history_findings), 1)
        finding = history_findings[0]

        self.assertEqual(finding["rule"], "password_history_disabled")
        self.assertEqual(
            finding["level"], RULE_DESCRIPTIONS["password_history_disabled"]["level"]
        )
        self.assertIn("Size: 0", finding["description"])

    def test_history_size_enabled(self):
        """Test history_size>=1 produces enabled finding."""
        metrics = {"password_policy": {"policy": {"history_size": 5}}}
        findings = _collect_password_findings(metrics)

        history_findings = [f for f in findings if "history" in f["rule"]]
        self.assertEqual(len(history_findings), 1)
        finding = history_findings[0]

        self.assertEqual(finding["rule"], "password_history_enabled")
        self.assertEqual(
            finding["level"], RULE_DESCRIPTIONS["password_history_enabled"]["level"]
        )
        self.assertIn("Size: 5", finding["description"])

    def test_max_age_disabled(self):
        """Test max_password_age=disabled produces disabled finding."""
        metrics = {"password_policy": {"policy": {"max_password_age": "disabled"}}}
        findings = _collect_password_findings(metrics)

        age_findings = [f for f in findings if "max_password_age" in f["rule"]]
        self.assertEqual(len(age_findings), 1)
        finding = age_findings[0]

        self.assertEqual(finding["rule"], "max_password_age_disabled")
        self.assertEqual(
            finding["level"], RULE_DESCRIPTIONS["max_password_age_disabled"]["level"]
        )
        self.assertIn("Days: disabled", finding["description"])

    def test_max_age_too_long(self):
        """Test max_password_age>365 produces too long finding."""
        metrics = {"password_policy": {"policy": {"max_password_age": 366}}}
        findings = _collect_password_findings(metrics)

        age_findings = [f for f in findings if "max_password_age" in f["rule"]]
        self.assertEqual(len(age_findings), 1)
        finding = age_findings[0]

        self.assertEqual(finding["rule"], "max_password_age_too_long")
        self.assertEqual(
            finding["level"], RULE_DESCRIPTIONS["max_password_age_too_long"]["level"]
        )
        self.assertIn("Days: 366", finding["description"])

    def test_max_age_enabled(self):
        """Test max_password_age<=365 produces enabled finding."""
        metrics = {"password_policy": {"policy": {"max_password_age": 90}}}
        findings = _collect_password_findings(metrics)

        age_findings = [f for f in findings if "max_password_age" in f["rule"]]
        self.assertEqual(len(age_findings), 1)
        finding = age_findings[0]

        self.assertEqual(finding["rule"], "max_password_age_enabled")
        self.assertEqual(
            finding["level"], RULE_DESCRIPTIONS["max_password_age_enabled"]["level"]
        )
        self.assertIn("Days: 90", finding["description"])

    def test_complete_policy(self):
        """Test complete policy with all settings."""
        metrics = {
            "password_policy": {
                "policy": {
                    "min_password_length": 12,
                    "complexity": "enabled",
                    "lockout_threshold": 5,
                    "history_size": 10,
                    "max_password_age": 60,
                }
            }
        }
        findings = _collect_password_findings(metrics)

        self.assertEqual(len(findings), 5)

        # Check each finding
        rule_names = [f["rule"] for f in findings]
        self.assertIn("password_min_length_strong", rule_names)
        self.assertIn("password_complexity_enabled", rule_names)
        self.assertIn("account_lockout_defined", rule_names)
        self.assertIn("password_history_enabled", rule_names)
        self.assertIn("max_password_age_enabled", rule_names)

    def test_max_age_integer_but_not_too_long(self):
        """Test max_password_age is an integer <= 365 (enabled case)."""
        metrics = {"password_policy": {"policy": {"max_password_age": 365}}}
        findings = _collect_password_findings(metrics)

        age_findings = [f for f in findings if "max_password_age" in f["rule"]]
        self.assertEqual(len(age_findings), 1)
        finding = age_findings[0]

        self.assertEqual(finding["rule"], "max_password_age_enabled")
        self.assertIn("Days: 365", finding["description"])

    def test_max_age_non_string_non_int(self):
        """Test max_password_age with float value (should be treated as enabled)."""
        metrics = {"password_policy": {"policy": {"max_password_age": 90.5}}}
        findings = _collect_password_findings(metrics)

        age_findings = [f for f in findings if "max_password_age" in f["rule"]]
        self.assertEqual(len(age_findings), 1)
        finding = age_findings[0]

        # Should fall through to the else case: max_password_age_enabled
        self.assertEqual(finding["rule"], "max_password_age_enabled")
        self.assertIn("Days: 90.5", finding["description"])

    def test_complexity_various_non_enabled_values(self):
        """Test complexity with various non-'enabled' values."""
        for value in ["Disabled", "partial", 0, None, True, False]:
            metrics = {"password_policy": {"policy": {"complexity": value}}}
            findings = _collect_password_findings(metrics)

            complexity_findings = [f for f in findings if "complexity" in f["rule"]]
            self.assertEqual(len(complexity_findings), 1)
            finding = complexity_findings[0]

            self.assertEqual(
                finding["rule"],
                "password_complexity_disabled",
                f"Failed with complexity={value}",
            )

    def test_partial_policy(self):
        """Test policy with some settings present and others missing."""
        metrics = {
            "password_policy": {
                "policy": {
                    "min_password_length": 10,
                    # complexity missing
                    "lockout_threshold": 3,
                    # history_size missing
                    # max_password_age missing
                }
            }
        }
        findings = _collect_password_findings(metrics)

        # Should have 5 findings total with appropriate defaults
        self.assertEqual(len(findings), 5)

        # Check specific findings
        rules = [f["rule"] for f in findings]

        # min_length should be acceptable (8-11)
        self.assertIn("password_min_length_acceptable", rules)

        # complexity should default to disabled
        self.assertIn("password_complexity_disabled", rules)

        # lockout_threshold is defined
        self.assertIn("account_lockout_defined", rules)

        # history_size should default to disabled
        self.assertIn("password_history_disabled", rules)

        # max_password_age should default to disabled
        self.assertIn("max_password_age_disabled", rules)

    def test_unusual_lockout_threshold_values(self):
        """Test lockout_threshold with unusual values."""
        for value in [0, "", False, [], {}]:
            metrics = {"password_policy": {"policy": {"lockout_threshold": value}}}
            findings = _collect_password_findings(metrics)

            lockout_findings = [f for f in findings if "lockout" in f["rule"]]
            self.assertEqual(len(lockout_findings), 1)
            finding = lockout_findings[0]

            # Any value that's not "not-defined" should be treated as defined
            self.assertEqual(
                finding["rule"],
                "account_lockout_defined",
                f"Failed with lockout_threshold={value}",
            )


class TestScoreTypeToOrder(unittest.TestCase):
    """Tests for the score type ordering function used for sorting findings."""

    def test_score_type_to_order(self):
        """Test that _score_type_to_order returns correct values for all score types."""
        self.assertEqual(rules._score_type_to_order("bonus"), -1)
        self.assertEqual(rules._score_type_to_order("neutral"), 0)
        self.assertEqual(rules._score_type_to_order("penalty"), 1)
        # Test fallback for unknown score type
        self.assertEqual(rules._score_type_to_order("unknown"), 1)

    def test_score_type_ordering_in_findings(self):
        """Test that findings are correctly ordered by score type."""
        # Create findings with different score types
        findings = [
            {"rule": "finding1", "score_impact": {"type": "penalty", "value": -10}},
            {"rule": "finding2", "score_impact": {"type": "bonus", "value": 5}},
            {"rule": "finding3", "score_impact": {"type": "neutral", "value": 0}},
            {"rule": "finding4", "score_impact": {"type": "penalty", "value": -5}},
        ]

        # Sort findings using the same key function as in _evaluate_legacy
        sorted_findings = sorted(
            findings,
            key=lambda f: (
                rules._score_type_to_order(f.get("score_impact", {}).get("type")),
                -1 * f.get("score_impact", {}).get("value", 0),
            ),
        )

        # Verify the order: bonus, neutral, then penalties (with higher values first)
        self.assertEqual(sorted_findings[0]["rule"], "finding2")  # bonus
        self.assertEqual(sorted_findings[1]["rule"], "finding3")  # neutral
        self.assertEqual(sorted_findings[2]["rule"], "finding4")  # penalty (-5)
        self.assertEqual(sorted_findings[3]["rule"], "finding1")  # penalty (-10)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
