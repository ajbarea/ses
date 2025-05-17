"""Security evaluation rules module.

Defines rule checks for system metrics, calculates penalties, and generates an
evaluation report with score, grade, summary, and detailed findings.
"""

from datetime import datetime, timezone

# Severity level → penalty point mapping.
SEVERITY_SCORES = {
    "critical": -30,
    "warning": -10,
    "info": -5,
}

# Maximum number of running services before issuing an informational finding.
SERVICE_COUNT_THRESHOLD = 300

# Human-readable descriptions and severity for each rule.
RULE_DESCRIPTIONS = {
    "patch_status": {
        "description": "System patches are not up-to-date.",
        "level": "critical",
    },
    "open_ports": {"description": "Open TCP ports found.", "level": "warning"},
    "service_count": {
        "description": "Number of running services exceeds threshold",
        "level": "info",
    },
}

# Check if PyCLIPS is available
CLIPS_AVAILABLE = False
try:
    import clips

    CLIPS_AVAILABLE = True
except ImportError:
    CLIPS_AVAILABLE = False


def calculate_score(findings: list, base_score: int = 100) -> int:
    """Compute the final security score after applying penalties.

    Args:
        findings (list): List of dicts each containing a 'level' key.
        base_score (int): Initial score before deductions.

    Returns:
        int: Adjusted score, clamped between 0 and 100.
    """
    score = base_score
    for finding in findings:
        level = finding.get("level", "info")
        penalty = SEVERITY_SCORES.get(level, -5)
        score += penalty
    return max(0, min(100, score))


def _evaluate_legacy(metrics: dict) -> dict:
    """Original rule-based evaluation using hardcoded Python rules.

    Args:
        metrics (dict): System metrics with keys like 'patch', 'ports', 'services'.

    Returns:
        dict: Evaluation report with findings and score.
    """
    findings = []
    if metrics["patch"]["status"] != "up-to-date":
        findings.append(
            {
                "rule": "patch_status",
                "level": "critical",
                "description": RULE_DESCRIPTIONS["patch_status"]["description"],
            }
        )
    if len(metrics["ports"]["ports"]) > 0:
        findings.append(
            {
                "rule": "open_ports",
                "level": "warning",
                "description": RULE_DESCRIPTIONS["open_ports"]["description"],
                "details": metrics["ports"]["ports"],
            }
        )

    # check if the number of running services exceeds the configured threshold
    service_count = len(metrics["services"]["services"])
    if service_count > SERVICE_COUNT_THRESHOLD:
        findings.append(
            {
                "rule": "service_count",
                "level": RULE_DESCRIPTIONS["service_count"]["level"],
                "description": RULE_DESCRIPTIONS["service_count"]["description"],
                "details": service_count,
            }
        )

    score = calculate_score(findings)
    grade = (
        "Excellent"
        if score >= 90
        else (
            "Good"
            if score >= 80
            else "Fair" if score >= 60 else "Poor" if score >= 40 else "Critical Risk"
        )
    )

    return {
        "score": score,
        "grade": grade,
        "summary": (
            "No critical issues found."
            if not findings
            else "; ".join(f["description"] for f in findings)
        ),
        "findings": findings,
    }


def _evaluate_clips(metrics: dict) -> dict:
    """Evaluate security using the CLIPS expert system.

    Args:
        metrics (dict): System metrics with keys like 'patch', 'ports', 'services'.

    Returns:
        dict: Evaluation report with findings, score, and explanations.
    """
    try:
        from clips_evaluator import SecurityExpertSystem

        expert_system = SecurityExpertSystem()
        result = expert_system.evaluate(metrics)
        return result
    except (ImportError, Exception) as e:
        print(f"Error using CLIPS evaluator: {e}")
        return _evaluate_legacy(metrics)


def evaluate(metrics: dict, use_clips: bool = None) -> dict:
    """Assess provided metrics against rules and assemble an evaluation report.

    Args:
        metrics (dict): System metrics with keys like 'patch', 'ports', 'services'.
        use_clips (bool, optional): Whether to use the CLIPS expert system.
            Defaults to None (auto-detect based on availability).

    Returns:
        dict: Evaluation report including:
            - timestamp (UTC ISO8601 string)
            - score (0–100)
            - grade (textual rating)
            - summary (concise findings overview)
            - findings (detailed rule violations)
            - metrics (raw input data)
    """
    # Determine whether to use CLIPS
    if use_clips is None:
        use_clips = CLIPS_AVAILABLE

    # Run the appropriate evaluation engine
    if use_clips and CLIPS_AVAILABLE:
        result = _evaluate_clips(metrics)
    else:
        result = _evaluate_legacy(metrics)

    # Add timestamp and metrics to the result
    result["timestamp"] = datetime.now(timezone.utc).isoformat()
    result["metrics"] = metrics

    return result
