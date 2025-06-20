import unittest
from src.scoring import (
    SEVERITY_SCORES,
    DEFAULT_BASE_SCORE,
    CRITICAL_RISK_GRADE,
    GRADE_THRESHOLDS,
    DEFAULT_FINDING_IMPACTS,
    SCORE_CHANGE_TYPES,
    calculate_score,
    assign_grade,
    get_finding_score_impact,
    apply_score_impacts,
    format_score_impact_text,
    get_clips_finding_impact,
    create_score_changes,
)


class TestScoringConstants(unittest.TestCase):
    """Test scoring constants and their values."""

    def test_severity_scores_mapping(self):
        """Test that severity scores have correct values."""
        self.assertEqual(SEVERITY_SCORES["critical"], -30)
        self.assertEqual(SEVERITY_SCORES["warning"], -10)
        self.assertEqual(SEVERITY_SCORES["minor"], -3)
        self.assertEqual(SEVERITY_SCORES["info"], 0)

    def test_default_base_score(self):
        """Test that default base score is 100."""
        self.assertEqual(DEFAULT_BASE_SCORE, 100)

    def test_critical_risk_grade_constant(self):
        """Test that critical risk grade constant is properly defined."""
        self.assertEqual(CRITICAL_RISK_GRADE, "Critical Risk")

    def test_grade_thresholds(self):
        """Test grade threshold mappings."""
        expected_thresholds = {
            "Excellent": 90,
            "Good": 80,
            "Fair": 60,
            "Poor": 40,
            CRITICAL_RISK_GRADE: 0,
        }
        self.assertEqual(GRADE_THRESHOLDS, expected_thresholds)

    def test_default_finding_impacts(self):
        """Test default CLIPS finding impact mappings."""
        expected_impacts = {
            "info": {"value": 0, "type": "neutral"},
            "minor": {"value": -3, "type": "penalty"},
            "warning": {"value": -10, "type": "penalty"},
            "critical": {"value": -30, "type": "penalty"},
        }
        self.assertEqual(DEFAULT_FINDING_IMPACTS, expected_impacts)

    def test_score_change_types(self):
        """Test score change type constants."""
        expected_types = {
            "INITIAL": "initial",
            "PENALTY": "penalty",
            "BONUS": "bonus",
            "NEUTRAL": "neutral",
        }
        self.assertEqual(SCORE_CHANGE_TYPES, expected_types)


class TestCalculateScore(unittest.TestCase):
    """Test the calculate_score function."""

    def test_calculate_score_no_findings(self):
        """Test score calculation with no findings."""
        findings = []
        score = calculate_score(findings)
        self.assertEqual(score, DEFAULT_BASE_SCORE)

    def test_calculate_score_with_default_base(self):
        """Test score calculation with default base score."""
        findings = [{"level": "warning"}]
        score = calculate_score(findings)
        self.assertEqual(score, 90)  # 100 - 10

    def test_calculate_score_with_custom_base(self):
        """Test score calculation with custom base score."""
        findings = [{"level": "minor"}]
        score = calculate_score(findings, base_score=80)
        self.assertEqual(score, 77)  # 80 - 3

    def test_calculate_score_multiple_findings(self):
        """Test score calculation with multiple findings."""
        findings = [
            {"level": "critical"},  # -30
            {"level": "warning"},  # -10
            {"level": "minor"},  # -3
            {"level": "info"},  # 0
        ]
        score = calculate_score(findings, base_score=100)
        self.assertEqual(score, 57)  # 100 - 30 - 10 - 3

    def test_calculate_score_unknown_level(self):
        """Test score calculation with unknown finding level."""
        findings = [{"level": "unknown"}]
        score = calculate_score(findings)
        self.assertEqual(score, 100)  # No penalty for unknown level

    def test_calculate_score_missing_level(self):
        """Test score calculation with missing level key."""
        findings = [{"description": "No level key"}]
        score = calculate_score(findings)
        self.assertEqual(score, 100)  # Defaults to 'info' level

    def test_calculate_score_clamping_lower_bound(self):
        """Test that score is clamped to 0 as lower bound."""
        findings = [{"level": "critical"} for _ in range(10)]  # -300 total
        score = calculate_score(findings, base_score=100)
        self.assertEqual(score, 0)

    def test_calculate_score_clamping_upper_bound(self):
        """Test that score is clamped to 100 as upper bound."""
        findings = []
        score = calculate_score(findings, base_score=150)
        self.assertEqual(score, 100)


class TestAssignGrade(unittest.TestCase):
    """Test the assign_grade function."""

    def test_assign_grade_excellent(self):
        """Test assignment of Excellent grade."""
        score = 95
        findings = [{"level": "minor"}]
        grade = assign_grade(score, findings)
        self.assertEqual(grade, "Excellent")

    def test_assign_grade_good(self):
        """Test assignment of Good grade."""
        score = 85
        findings = [{"level": "warning"}]
        grade = assign_grade(score, findings)
        self.assertEqual(grade, "Good")

    def test_assign_grade_fair(self):
        """Test assignment of Fair grade."""
        score = 65
        findings = [{"level": "warning"}]
        grade = assign_grade(score, findings)
        self.assertEqual(grade, "Fair")

    def test_assign_grade_poor(self):
        """Test assignment of Poor grade."""
        score = 45
        findings = [{"level": "minor"}]
        grade = assign_grade(score, findings)
        self.assertEqual(grade, "Poor")

    def test_assign_grade_critical_risk_low_score(self):
        """Test assignment of Critical Risk grade for low scores."""
        score = 30
        findings = [{"level": "warning"}]
        grade = assign_grade(score, findings)
        self.assertEqual(grade, CRITICAL_RISK_GRADE)

    def test_assign_grade_one_critical_finding(self):
        """Test grade assignment with one critical finding."""
        score = 95
        findings = [{"level": "critical"}]
        grade = assign_grade(score, findings)
        # Effective score: 95 - 10 = 85, should be "Good"
        self.assertEqual(grade, "Good")

    def test_assign_grade_two_critical_findings(self):
        """Test grade assignment with two critical findings."""
        score = 95
        findings = [{"level": "critical"}, {"level": "critical"}]
        grade = assign_grade(score, findings)
        # Effective score: 95 - 20 = 75, should be "Fair"
        self.assertEqual(grade, "Fair")

    def test_assign_grade_three_critical_findings(self):
        """Test grade assignment with three or more critical findings."""
        score = 100
        findings = [{"level": "critical"} for _ in range(3)]
        grade = assign_grade(score, findings)
        self.assertEqual(grade, CRITICAL_RISK_GRADE)

    def test_assign_grade_mixed_findings_with_critical(self):
        """Test grade assignment with mixed findings including critical."""
        score = 80
        findings = [{"level": "critical"}, {"level": "warning"}, {"level": "minor"}]
        grade = assign_grade(score, findings)
        # Effective score: 80 - 10 = 70, should be "Fair"
        self.assertEqual(grade, "Fair")

    def test_assign_grade_below_all_thresholds(self):
        """Test that scores below all thresholds return Critical Risk grade."""
        score = -1
        findings = [{"level": "warning"}]
        result = assign_grade(score, findings)
        self.assertEqual(result, CRITICAL_RISK_GRADE)

    def test_assign_grade_exactly_zero(self):
        """Test that a score of exactly zero returns Critical Risk grade."""
        score = 0
        findings = [{"level": "warning"}]
        result = assign_grade(score, findings)
        self.assertEqual(result, CRITICAL_RISK_GRADE)


class TestGetFindingScoreImpact(unittest.TestCase):
    """Test the get_finding_score_impact function."""

    def test_get_finding_score_impact_critical(self):
        """Test impact calculation for critical findings."""
        finding = {"level": "critical"}
        impact = get_finding_score_impact(finding)
        self.assertEqual(impact["type"], "penalty")
        self.assertEqual(impact["value"], -30)

    def test_get_finding_score_impact_warning(self):
        """Test impact calculation for warning findings."""
        finding = {"level": "warning"}
        impact = get_finding_score_impact(finding)
        self.assertEqual(impact["type"], "penalty")
        self.assertEqual(impact["value"], -10)

    def test_get_finding_score_impact_minor(self):
        """Test impact calculation for minor findings."""
        finding = {"level": "minor"}
        impact = get_finding_score_impact(finding)
        self.assertEqual(impact["type"], "penalty")
        self.assertEqual(impact["value"], -3)

    def test_get_finding_score_impact_info(self):
        """Test impact calculation for info findings."""
        finding = {"level": "info"}
        impact = get_finding_score_impact(finding)
        self.assertEqual(impact["type"], "neutral")
        self.assertEqual(impact["value"], 0)

    def test_get_finding_score_impact_unknown_level(self):
        """Test impact calculation for unknown level."""
        finding = {"level": "unknown"}
        impact = get_finding_score_impact(finding)
        self.assertEqual(impact["type"], "penalty")
        self.assertEqual(impact["value"], 0)

    def test_get_finding_score_impact_missing_level(self):
        """Test impact calculation for missing level key."""
        finding = {"description": "No level"}
        impact = get_finding_score_impact(finding)
        self.assertEqual(impact["type"], "neutral")
        self.assertEqual(impact["value"], 0)


class TestApplyScoreImpacts(unittest.TestCase):
    """Test the apply_score_impacts function."""

    def test_apply_score_impacts_none_impacts(self):
        """Test that apply_score_impacts handles None impacts correctly."""
        result = apply_score_impacts(base_score=100, impacts=None)
        self.assertEqual(result, 100)

    def test_apply_score_impacts_empty_impacts(self):
        """Test with empty impacts list."""
        result = apply_score_impacts(base_score=100, impacts=[])
        self.assertEqual(result, 100)

    def test_apply_score_impacts_with_penalties(self):
        """Test applying penalty impacts."""
        impacts = [
            {"type": "penalty", "value": -10},
            {"type": "penalty", "value": -5},
        ]
        result = apply_score_impacts(base_score=100, impacts=impacts)
        self.assertEqual(result, 85)

    def test_apply_score_impacts_with_bonuses(self):
        """Test applying bonus impacts."""
        impacts = [
            {"type": "bonus", "value": 10},
            {"type": "bonus", "value": 5},
        ]
        result = apply_score_impacts(base_score=80, impacts=impacts)
        self.assertEqual(result, 95)

    def test_apply_score_impacts_mixed(self):
        """Test applying mixed penalty and bonus impacts."""
        impacts = [
            {"type": "penalty", "value": -10},
            {"type": "bonus", "value": 5},
            {"type": "neutral", "value": 100},  # Should be ignored
        ]
        result = apply_score_impacts(base_score=100, impacts=impacts)
        self.assertEqual(result, 95)

    def test_apply_score_impacts_default_base_score(self):
        """Test that apply_score_impacts uses DEFAULT_BASE_SCORE when not specified."""
        result = apply_score_impacts(impacts=[])
        self.assertEqual(result, DEFAULT_BASE_SCORE)

    def test_apply_score_impacts_clamping_lower(self):
        """Test score clamping to lower bound."""
        impacts = [{"type": "penalty", "value": -150}]
        result = apply_score_impacts(base_score=100, impacts=impacts)
        self.assertEqual(result, 0)

    def test_apply_score_impacts_clamping_upper(self):
        """Test score clamping to upper bound."""
        impacts = [{"type": "bonus", "value": 50}]
        result = apply_score_impacts(base_score=80, impacts=impacts)
        self.assertEqual(result, 100)


class TestFormatScoreImpactText(unittest.TestCase):
    """Test the format_score_impact_text function."""

    def test_format_penalty_impact(self):
        """Test formatting penalty impacts."""
        impact = {"type": "penalty", "value": -10}
        result = format_score_impact_text(impact)
        self.assertEqual(result, "-10 points")

    def test_format_bonus_impact(self):
        """Test formatting bonus impacts."""
        impact = {"type": "bonus", "value": 5}
        result = format_score_impact_text(impact)
        self.assertEqual(result, "+5 points")

    def test_format_neutral_impact(self):
        """Test formatting neutral impacts."""
        impact = {"type": "neutral", "value": 0}
        result = format_score_impact_text(impact)
        self.assertEqual(result, "0 points (neutral)")

    def test_format_unknown_impact_type(self):
        """Test formatting unknown impact types."""
        impact = {"type": "unknown", "value": 10}
        result = format_score_impact_text(impact)
        self.assertEqual(result, "0 points (neutral)")

    def test_format_missing_values(self):
        """Test formatting with missing type or value."""
        impact = {}
        result = format_score_impact_text(impact)
        self.assertEqual(result, "0 points (neutral)")

    def test_format_negative_penalty(self):
        """Test formatting penalty with negative value (abs should handle it)."""
        impact = {"type": "penalty", "value": -25}
        result = format_score_impact_text(impact)
        self.assertEqual(result, "-25 points")


class TestGetClipsFindingImpact(unittest.TestCase):
    """Test the get_clips_finding_impact function."""

    def test_get_clips_finding_impact_critical(self):
        """Test CLIPS impact for critical findings."""
        finding = {"level": "critical"}
        impact = get_clips_finding_impact(finding)
        self.assertEqual(impact["type"], "penalty")
        self.assertEqual(impact["value"], -30)

    def test_get_clips_finding_impact_warning(self):
        """Test CLIPS impact for warning findings."""
        finding = {"level": "warning"}
        impact = get_clips_finding_impact(finding)
        self.assertEqual(impact["type"], "penalty")
        self.assertEqual(impact["value"], -10)

    def test_get_clips_finding_impact_minor(self):
        """Test CLIPS impact for minor findings."""
        finding = {"level": "minor"}
        impact = get_clips_finding_impact(finding)
        self.assertEqual(impact["type"], "penalty")
        self.assertEqual(impact["value"], -3)

    def test_get_clips_finding_impact_info(self):
        """Test CLIPS impact for info findings."""
        finding = {"level": "info"}
        impact = get_clips_finding_impact(finding)
        self.assertEqual(impact["type"], "neutral")
        self.assertEqual(impact["value"], 0)

    def test_get_clips_finding_impact_unknown_level(self):
        """Test CLIPS impact for unknown level."""
        finding = {"level": "unknown"}
        impact = get_clips_finding_impact(finding)
        self.assertEqual(impact["type"], "neutral")
        self.assertEqual(impact["value"], 0)

    def test_get_clips_finding_impact_missing_level(self):
        """Test CLIPS impact for missing level key."""
        finding = {"description": "No level"}
        impact = get_clips_finding_impact(finding)
        self.assertEqual(impact["type"], "neutral")
        self.assertEqual(impact["value"], 0)

    def test_get_clips_finding_impact_copy(self):
        """Test that get_clips_finding_impact returns a copy."""
        finding = {"level": "warning"}
        impact1 = get_clips_finding_impact(finding)
        impact2 = get_clips_finding_impact(finding)
        # Modify one impact
        impact1["custom"] = "modified"
        # Ensure the other is not affected
        self.assertNotIn("custom", impact2)


class TestCreateScoreChanges(unittest.TestCase):
    """Test the create_score_changes function."""

    def test_create_score_changes_base_only(self):
        """Test creating score changes with only base score."""
        base_score = 100
        findings = []
        changes = create_score_changes(base_score, findings)

        expected = [
            {
                "rule": "base_score",
                "delta": 100,
                "type": "initial",
            }
        ]
        self.assertEqual(changes, expected)

    def test_create_score_changes_with_findings(self):
        """Test creating score changes with findings that have score impacts."""
        base_score = 100
        findings = [
            {"rule": "test_rule_1", "score_impact": {"value": -10, "type": "penalty"}},
            {
                "rule-name": "test_rule_2",  # Alternative key format
                "score_impact": {"value": -5, "type": "penalty"},
            },
        ]
        changes = create_score_changes(base_score, findings)

        expected = [
            {
                "rule": "base_score",
                "delta": 100,
                "type": "initial",
            },
            {
                "rule": "test_rule_1",
                "delta": -10,
                "type": "penalty",
            },
            {
                "rule": "test_rule_2",
                "delta": -5,
                "type": "penalty",
            },
        ]
        self.assertEqual(changes, expected)

    def test_create_score_changes_no_score_impact(self):
        """Test creating score changes with findings that have no score impact."""
        base_score = 100
        findings = [{"rule": "no_impact_rule", "description": "No score impact"}]
        changes = create_score_changes(base_score, findings)

        expected = [
            {
                "rule": "base_score",
                "delta": 100,
                "type": "initial",
            }
        ]
        self.assertEqual(changes, expected)

    def test_create_score_changes_missing_rule_name(self):
        """Test creating score changes with findings missing rule names."""
        base_score = 100
        findings = [
            {
                "description": "No rule name",
                "score_impact": {"value": -7, "type": "penalty"},
            }
        ]
        changes = create_score_changes(base_score, findings)

        expected = [
            {
                "rule": "base_score",
                "delta": 100,
                "type": "initial",
            },
            {
                "rule": "",  # Empty string when no rule name found
                "delta": -7,
                "type": "penalty",
            },
        ]
        self.assertEqual(changes, expected)


class TestIntegrationScenarios(unittest.TestCase):
    """Integration tests for common scoring scenarios."""

    def test_scenario_clean_system(self):
        """Test scoring for a clean system with no findings."""
        findings = []
        score = calculate_score(findings)
        grade = assign_grade(score, findings)

        self.assertEqual(score, 100)
        self.assertEqual(grade, "Excellent")

    def test_scenario_minor_issues_only(self):
        """Test scoring with only minor issues."""
        findings = [
            {"level": "minor"},
            {"level": "minor"},
            {"level": "info"},
        ]
        score = calculate_score(findings)
        grade = assign_grade(score, findings)

        self.assertEqual(score, 94)  # 100 - 3 - 3
        self.assertEqual(grade, "Excellent")

    def test_scenario_mixed_severity(self):
        """Test scoring with mixed severity findings."""
        findings = [
            {"level": "warning"},
            {"level": "minor"},
            {"level": "minor"},
            {"level": "info"},
        ]
        score = calculate_score(findings)
        grade = assign_grade(score, findings)

        self.assertEqual(score, 84)  # 100 - 10 - 3 - 3
        self.assertEqual(grade, "Good")

    def test_scenario_single_critical(self):
        """Test scoring with single critical finding."""
        findings = [
            {"level": "critical"},
            {"level": "warning"},
        ]
        score = calculate_score(findings)
        grade = assign_grade(score, findings)

        self.assertEqual(score, 60)  # 100 - 30 - 10
        # With one critical: effective score = 60 - 10 = 50, grade = "Poor"
        self.assertEqual(grade, "Poor")

    def test_scenario_multiple_critical(self):
        """Test scoring with multiple critical findings."""
        findings = [
            {"level": "critical"},
            {"level": "critical"},
            {"level": "critical"},
        ]
        score = calculate_score(findings)
        grade = assign_grade(score, findings)

        self.assertEqual(score, 10)  # 100 - 30 - 30 - 30
        # Three critical findings always result in Critical Risk
        self.assertEqual(grade, CRITICAL_RISK_GRADE)

    def test_legacy_penalty_values(self):
        """Test that penalty values match the updated scoring system."""
        # This test ensures we're using the new -3 penalty for minor instead of -5
        findings = [
            {"level": "minor"},  # -3
            {"level": "minor"},  # -3
            {"level": "warning"},  # -10
            {"level": "info"},  # 0
        ]

        score = calculate_score(findings, base_score=100)
        expected_score = 100 - 3 - 3 - 10  # = 84
        self.assertEqual(score, expected_score)

        # Verify individual impacts
        minor_impact = get_finding_score_impact({"level": "minor"})
        self.assertEqual(minor_impact["value"], -3)

        clips_impact = get_clips_finding_impact({"level": "minor"})
        self.assertEqual(clips_impact["value"], -3)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
