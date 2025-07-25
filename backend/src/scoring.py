"""Centralized scoring system for security evaluation.

Provides constants, functions, and utilities for calculating security scores
across different evaluation engines (legacy Python and CLIPS).
"""

# Master mapping of severity to numeric score delta
SEVERITY_SCORES = {
    "critical": -30,  # severe security issues
    "warning": -10,  # moderate issues
    "minor": -3,  # minor violations that need attention
    "info": 0,  # informational findings, no score change
}

# Base score to start from
DEFAULT_BASE_SCORE = 100
CRITICAL_RISK_GRADE = "Critical Risk"

# Score thresholds for grade determination
GRADE_THRESHOLDS = {
    "Excellent": 90,
    "Good": 80,
    "Fair": 60,
    "Poor": 40,
    CRITICAL_RISK_GRADE: 0,  # Anything below 40 or with critical findings
}

# Default score mappings for CLIPS findings
DEFAULT_FINDING_IMPACTS = {
    "info": {"value": 0, "type": "neutral"},
    "minor": {"value": -3, "type": "penalty"},
    "warning": {"value": -10, "type": "penalty"},
    "critical": {"value": -30, "type": "penalty"},
}

# Score thresholds for grade determination (in descending order)
SCORE_GRADE_THRESHOLDS = {
    90: "Excellent",
    80: "Good",
    60: "Fair",
    40: "Poor",
    0: CRITICAL_RISK_GRADE,
}

# Score change type constants
SCORE_CHANGE_TYPES = {
    "INITIAL": "initial",
    "PENALTY": "penalty",
    "BONUS": "bonus",
    "NEUTRAL": "neutral",
}


def calculate_score(findings: list, base_score: int = DEFAULT_BASE_SCORE) -> int:
    """Calculate security score by applying penalties for findings.

    Starts with the base score and deducts points based on the severity
    of each finding, clamping the result to a 0-100 range.

    Args:
        findings: List of finding dictionaries, each with a 'level' key
        base_score: Starting score before penalties (default: 100)

    Returns:
        Final security score (0-100)
    """
    score = base_score
    for finding in findings:
        level = finding.get(
            "level", "info"
        )  # Default to 'info' if level is not specified
        penalty = SEVERITY_SCORES.get(level, 0)  # Default penalty if level is unknown
        score += penalty
    return max(0, min(100, score))  # Ensure score is within 0-100 range


def assign_grade(score: int, findings: list) -> str:
    """Determine security grade based on score and findings.

    Args:
        score: Numeric security score (0-100)
        findings: List of finding dictionaries

    Returns:
        String grade representing security level
    """
    # Count critical findings
    critical_count = sum(1 for f in findings if f.get("level") == "critical")

    # Multiple critical findings (3+) always result in Critical Risk
    if critical_count >= 3:
        return CRITICAL_RISK_GRADE

    # Single critical finding can still get better grades if score is decent
    if critical_count == 1:
        # Reduce effective score by 10 points for the critical finding
        effective_score = max(0, score - 10)
    elif critical_count == 2:
        # Reduce effective score by 20 points for two critical findings
        effective_score = max(0, score - 20)
    else:
        effective_score = score

    # Grade based on effective score thresholds
    for grade, threshold in sorted(GRADE_THRESHOLDS.items(), key=lambda x: -x[1]):
        if grade == CRITICAL_RISK_GRADE:
            continue
        if effective_score >= threshold:
            return grade

    # If no other grade matched, return Critical Risk
    return CRITICAL_RISK_GRADE


def get_finding_score_impact(finding: dict) -> dict:
    """Determine the score impact of a finding based on its level.

    Args:
        finding: A finding dictionary with a 'level' key

    Returns:
        Dictionary with 'type' and 'value' keys
    """
    level = finding.get("level", "info")
    value = SEVERITY_SCORES.get(level, 0)

    if level == "info":
        impact_type = "neutral"
    else:
        impact_type = "penalty"

    return {"type": impact_type, "value": value}


def apply_score_impacts(
    base_score: int = DEFAULT_BASE_SCORE, impacts: list = None
) -> int:
    """Apply a list of score impacts to calculate final score.

    Args:
        base_score: Starting score value (default: 100)
        impacts: List of impact dictionaries with 'type' and 'value' keys

    Returns:
        Final score clamped between 0 and 100
    """
    if impacts is None:
        impacts = []

    score = base_score

    for impact in impacts:
        impact_type = impact.get("type", "neutral")
        value = impact.get("value", 0)

        if impact_type in ("penalty", "bonus"):
            score += value  # Penalties are negative values

    return max(0, min(100, score))  # Clamp to 0-100 range


def format_score_impact_text(impact: dict) -> str:
    """Format a score impact as a user-friendly text string.

    Args:
        impact: Dictionary with 'type' and 'value' keys

    Returns:
        Formatted string representation of the score impact
    """
    impact_type = impact.get("type", "neutral")
    value = impact.get("value", 0)

    if impact_type == "penalty":
        return f"-{abs(value)} points"
    elif impact_type == "bonus":
        return f"+{value} points"
    else:
        return "0 points (neutral)"


def get_clips_finding_impact(finding: dict) -> dict:
    """Get the score impact for a CLIPS finding based on its level.

    Args:
        finding: Dictionary with 'level' key from CLIPS finding fact

    Returns:
        Dictionary with 'type' and 'value' keys
    """
    level = finding.get("level", "info")
    return DEFAULT_FINDING_IMPACTS.get(level, {"value": 0, "type": "neutral"}).copy()


def create_score_changes(base_score: int, findings: list) -> list:
    """Create a list of score changes from findings."""
    score_changes = [
        {
            "rule": "base_score",
            "delta": base_score,
            "type": SCORE_CHANGE_TYPES["INITIAL"],
        }
    ]

    for finding in findings:
        if impact := finding.get("score_impact"):
            rule_name = finding.get("rule", finding.get("rule-name", ""))
            score_changes.append(
                {"rule": rule_name, "delta": impact["value"], "type": impact["type"]}
            )

    return score_changes
