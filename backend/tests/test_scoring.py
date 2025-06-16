import unittest
from src.scoring import (
    assign_grade,
    CRITICAL_RISK_GRADE,
    apply_score_impacts,
    DEFAULT_BASE_SCORE,
)


class TestScoring(unittest.TestCase):
    def test_assign_grade_below_all_thresholds(self):
        """Test that scores below all thresholds return Critical Risk grade."""
        score = -1  # Score below all thresholds (lowest is 0)
        findings = [{"level": "warning"}]  # No critical findings
        result = assign_grade(score, findings)
        self.assertEqual(result, CRITICAL_RISK_GRADE)

    def test_assign_grade_exactly_zero(self):
        """Test that a score of exactly zero returns Critical Risk grade."""
        score = 0  # Score at the lowest threshold
        findings = [{"level": "warning"}]  # No critical findings
        result = assign_grade(score, findings)
        self.assertEqual(result, CRITICAL_RISK_GRADE)

    def test_apply_score_impacts_none_impacts(self):
        """Test that apply_score_impacts handles None impacts correctly."""
        result = apply_score_impacts(base_score=100, impacts=None)
        self.assertEqual(result, 100)

    def test_apply_score_impacts_with_impacts(self):
        """Test that apply_score_impacts correctly applies score impacts."""
        impacts = [
            {"type": "penalty", "value": -10},
            {"type": "bonus", "value": 5},
        ]
        result = apply_score_impacts(base_score=100, impacts=impacts)
        self.assertEqual(result, 95)

    def test_apply_score_impacts_default_base_score(self):
        """Test that apply_score_impacts uses DEFAULT_BASE_SCORE when not specified."""
        result = apply_score_impacts(impacts=[])
        self.assertEqual(result, DEFAULT_BASE_SCORE)


if __name__ == "__main__":
    unittest.main()
