"""Security rule engine for evaluating Windows system security metrics.

Processes system metrics to generate security findings, calculate scores,
and determine an overall security grade for the system.
"""

from datetime import datetime, timezone
from typing import Optional
from src.logging_config import get_logger

logger = get_logger(__name__)

# Penalty points for finding severity levels
SEVERITY_SCORES = {
    "critical": -30,
    "warning": -10,
    "info": -5,
}

# Threshold for number of running services before triggering an alert
SERVICE_COUNT_THRESHOLD = 300

# Rule definitions with descriptions and severity levels
RULE_DESCRIPTIONS = {
    "patch_status": {
        "description": "System patches are not up-to-date.",
        "level": "critical",
    },
    "open_ports": {
        "description": "Open TCP ports found.",
        "level": "warning",
    },
    "service_count": {
        "description": "Number of running services exceeds threshold",
        "level": "info",
    },
    "firewall_all_disabled": {
        "description": "All firewall profiles are disabled.",
        "level": "critical",
    },
    "firewall_public_disabled": {
        "description": "Public firewall profile is disabled.",
        "level": "warning",
    },
    "firewall_domain_disabled": {
        "description": "Domain firewall profile is disabled.",
        "level": "warning",
    },
    "firewall_private_disabled": {
        "description": "Private firewall profile is disabled.",
        "level": "warning",
    },
    "firewall_all_enabled": {
        "description": "All firewall profiles are enabled.",
        "level": "info",
    },
    "antivirus_not_detected": {
        "description": "No antivirus products detected.",
        "level": "critical",
    },
}

# Check if CLIPS expert system is available
CLIPS_AVAILABLE = False
try:
    import clips

    CLIPS_AVAILABLE = True
    logger.info("CLIPS module successfully imported")
except ImportError as e:  # pragma: no cover
    CLIPS_AVAILABLE = False  # CLIPS is not installed or importable
    logger.warning(f"CLIPS import error: {e}")
except Exception:  # pragma: no cover
    CLIPS_AVAILABLE = False
# Log the CLIPS availability status for debugging
logger.info(
    f"CLIPS availability: {'AVAILABLE' if CLIPS_AVAILABLE else 'NOT AVAILABLE'}"
)


def calculate_score(findings: list, base_score: int = 100) -> int:
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
        penalty = SEVERITY_SCORES.get(level, -5)  # Default penalty if level is unknown
        score += penalty
    return max(0, min(100, score))  # Ensure score is within 0-100 range


def _collect_patch_findings(metrics):
    """Extract patch status findings."""
    findings = []
    if metrics["patch"]["status"] != "up-to-date":
        findings.append(
            {
                "rule": "patch_status",
                "level": "critical",
                "description": RULE_DESCRIPTIONS["patch_status"]["description"],
            }
        )
    return findings


def _collect_ports_findings(metrics):
    """Extract open ports findings."""
    ports = metrics["ports"]["ports"]
    if ports:
        return [
            {
                "rule": "open_ports",
                "level": "warning",
                "description": RULE_DESCRIPTIONS["open_ports"]["description"],
                "details": ports,
            }
        ]
    return []


def _collect_service_count_findings(metrics):
    """Extract service count findings."""
    count = len(metrics["services"]["services"])
    if count > SERVICE_COUNT_THRESHOLD:
        return [
            {
                "rule": "service_count",
                "level": RULE_DESCRIPTIONS["service_count"]["level"],
                "description": RULE_DESCRIPTIONS["service_count"]["description"],
                "details": count,
            }
        ]
    return []


def _collect_firewall_findings(metrics):
    """Extract firewall status findings."""
    findings = []
    profiles = metrics.get("firewall", {}).get("profiles", {})
    d, p, u = profiles.get("domain"), profiles.get("private"), profiles.get("public")

    # Check if all profiles are disabled
    if all(v == "OFF" for v in (d, p, u)):
        key = "firewall_all_disabled"
        findings.append(
            {
                "rule": key,
                "level": RULE_DESCRIPTIONS[key]["level"],
                "description": RULE_DESCRIPTIONS[key]["description"],
            }
        )
        return findings

    # Check individual disabled profiles
    for prof in ("public", "domain", "private"):
        if profiles.get(prof) == "OFF":
            key = f"firewall_{prof}_disabled"
            findings.append(
                {
                    "rule": key,
                    "level": RULE_DESCRIPTIONS[key]["level"],
                    "description": RULE_DESCRIPTIONS[key]["description"],
                }
            )

    # Check if all profiles are enabled
    if all(v == "ON" for v in (d, p, u)):
        key = "firewall_all_enabled"
        findings.append(
            {
                "rule": key,
                "level": RULE_DESCRIPTIONS[key]["level"],
                "description": RULE_DESCRIPTIONS[key]["description"],
            }
        )

    return findings


def _collect_antivirus_findings(metrics):
    """Extract antivirus status findings."""
    findings = []
    products = metrics.get("antivirus", {}).get("products", [])

    # Check if no antivirus products detected
    if not products:
        key = "antivirus_not_detected"
        findings.append(
            {
                "rule": key,
                "level": RULE_DESCRIPTIONS[key]["level"],
                "description": RULE_DESCRIPTIONS[key]["description"],
            }
        )
    else:
        # Check for antivirus products with unknown state
        for p in products:
            if p.get("state") is None:
                findings.append(
                    {
                        "rule": f"antivirus_{p['name']}_unknown",
                        "level": "warning",
                        "description": f"Antivirus product {p['name']} state unknown.",
                    }
                )
    return findings


def _assign_grade(score, findings):
    """Determine security grade based on score and findings.

    Args:
        score: Numeric security score (0-100)
        findings: List of finding dictionaries

    Returns:
        String grade representing security level
    """
    # Critical findings always result in Critical Risk grade
    if any(f["level"] == "critical" for f in findings):
        return "Critical Risk"

    # Otherwise grade based on score
    if score >= 90:
        return "Excellent"
    if score >= 80:
        return "Good"
    if score >= 60:
        return "Fair"
    if score >= 40:
        return "Poor"
    return "Critical Risk"


def _evaluate_legacy(metrics: dict) -> dict:
    """Evaluate metrics with Python-based rules and generate security findings.

    Applies built-in rule sets to the system metrics and generates findings,
    calculates an overall security score, and assigns a grade.

    Args:
        metrics: Dictionary of system security metrics by category

    Returns:
        Evaluation results with score, grade, findings, and summary
    """
    findings = []
    findings.extend(_collect_patch_findings(metrics))
    findings.extend(_collect_ports_findings(metrics))
    findings.extend(_collect_service_count_findings(metrics))
    findings.extend(_collect_firewall_findings(metrics))
    if "antivirus" in metrics:
        findings.extend(_collect_antivirus_findings(metrics))

    score = calculate_score(findings)
    grade = _assign_grade(score, findings)
    summary = (
        "No critical issues found."
        if not findings
        else "; ".join(f["description"] for f in findings)
    )

    return {
        "score": score,
        "grade": grade,
        "summary": summary,
        "findings": findings,
        "rules_fired": len(findings),
        "explanations": [],
    }


def _evaluate_clips(metrics: dict) -> dict:
    """Evaluate metrics with the CLIPS expert system rule engine.

    Uses the SecurityExpertSystem to apply CLIPS rules to system metrics,
    falling back to legacy evaluation if CLIPS fails.

    Args:
        metrics: Dictionary of system security metrics by category

    Returns:
        Evaluation results from CLIPS engine or legacy fallback
    """
    try:
        from src.clips_evaluator import SecurityExpertSystem

        expert_system = SecurityExpertSystem()
        result = expert_system.evaluate(metrics)
        return result
    except Exception as e:
        logger.error(
            f"Error using CLIPS evaluator: {e}. Falling back to legacy evaluator."
        )
        return _evaluate_legacy(metrics)


def evaluate(metrics: dict, use_clips: Optional[bool] = None) -> dict:
    """Evaluate system security and generate findings, score, and grade.

    Main entry point for security evaluation, selecting between CLIPS
    or legacy evaluation engine based on availability and preferences.

    Args:
        metrics: Dictionary of system security metrics by category
        use_clips: Whether to use CLIPS engine (None=auto, True=force, False=legacy)

    Returns:
        Complete evaluation report with findings, score, grade, and metadata
    """
    # Determine evaluation engine based on preference and availability
    should_use_clips = CLIPS_AVAILABLE
    if use_clips is not None:
        should_use_clips = use_clips

    # Run appropriate evaluation
    if should_use_clips and CLIPS_AVAILABLE:
        logger.info("Using CLIPS evaluation engine.")
        result = _evaluate_clips(metrics)
    else:
        if should_use_clips and not CLIPS_AVAILABLE:
            logger.warning(
                "CLIPS evaluation requested but not available. Falling back to legacy."
            )
        logger.info("Using legacy Python evaluation engine.")
        result = _evaluate_legacy(metrics)

    # Add metadata to result
    result["timestamp"] = datetime.now(timezone.utc).isoformat()
    result["metrics"] = metrics

    return result
