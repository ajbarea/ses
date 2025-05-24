"""Security evaluation rule engine.

Implements both traditional Python-based and CLIPS-based security assessment.
Provides configurable rule definitions, scoring logic, and report generation
for system security metrics evaluation.
"""

from datetime import datetime

# Penalty points by finding severity level
SEVERITY_SCORES = {
    "critical": -30,
    "warning": -10,
    "info": -5,
}

# Alert threshold for excessive running services
SERVICE_COUNT_THRESHOLD = 300

# Rule definitions with severity levels and descriptions
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

# Detect CLIPS expert system availability
CLIPS_AVAILABLE = False
try:
    import clips

    CLIPS_AVAILABLE = True
# pragma: no cover
except ImportError:
    CLIPS_AVAILABLE = False  # pragma: no cover


def calculate_score(findings: list, base_score: int = 100) -> int:
    """Calculate final security score by applying severity-based penalties.

    Applies configured penalty points for each finding based on severity level.
    Ensures final score remains within valid range (0-100).

    Args:
        findings: List of finding dictionaries with severity levels
        base_score: Starting score before penalties (default: 100)

    Returns:
        Final security score between 0 and 100
    """
    score = base_score
    for finding in findings:
        level = finding.get("level", "info")
        penalty = SEVERITY_SCORES.get(level, -5)
        score += penalty
    return max(0, min(100, score))


def _evaluate_legacy(metrics: dict) -> dict:
    """Evaluate security using built-in Python rule engine.

    Applies predefined rules to system metrics, generates findings,
    and calculates overall security score without CLIPS dependency.

    Args:
        metrics: System security metrics by category

    Returns:
        Evaluation report with findings and calculated score
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
    """Evaluate security using CLIPS expert system engine.

    Attempts CLIPS-based evaluation with fallback to legacy engine
    if CLIPS initialization fails.

    Args:
        metrics: System security metrics by category

    Returns:
        Enhanced evaluation report with findings, score, and rule explanations
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
    """Perform security evaluation using preferred rule engine.

    Primary evaluation interface that:
    1. Selects appropriate rule engine (CLIPS or legacy)
    2. Executes evaluation against provided metrics
    3. Enriches results with metadata (timestamp, raw metrics)

    Args:
        metrics: System security metrics by category
        use_clips: Force CLIPS engine selection (default: auto-detect)

    Returns:
        Complete evaluation report with all supporting data
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
    result["timestamp"] = datetime.now().isoformat()
    result["metrics"] = metrics

    return result
