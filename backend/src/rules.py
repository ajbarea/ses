"""Security rule engine. Scores metrics, creates findings, and assigns a grade."""

from datetime import datetime, timezone
from typing import Optional
from src.logging_config import get_logger

logger = get_logger(__name__)

# Penalty points associated with different finding severity levels.
SEVERITY_SCORES = {
    "critical": -30,
    "warning": -10,
    "info": -5,
}

# Threshold for the number of running services before an 'info' alert is triggered.
SERVICE_COUNT_THRESHOLD = 300

# Descriptions and severity levels for predefined security rules.
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

# Flag indicating whether the CLIPS expert system library is available.
CLIPS_AVAILABLE = False
try:
    import clips

    CLIPS_AVAILABLE = True
    logger.info("CLIPS module successfully imported")
except ImportError as e:  # pragma: no cover
    CLIPS_AVAILABLE = False  # CLIPS is not installed or importable.
    logger.warning(f"CLIPS import error: {e}")
except Exception:  # pragma: no cover
    CLIPS_AVAILABLE = False
# Log the CLIPS availability status for debugging
logger.info(
    f"CLIPS availability: {'AVAILABLE' if CLIPS_AVAILABLE else 'NOT AVAILABLE'}"
)


# Function to calculate the final security score based on findings.
def calculate_score(findings: list, base_score: int = 100) -> int:
    """Calculate the final security score by applying penalties for each finding.

    The score starts at `base_score` and penalties are applied for each finding
    according to its severity level defined in `SEVERITY_SCORES`.
    The final score is clamped between 0 and 100.

    Args:
        findings: A list of finding dictionaries. Each dictionary should
                  contain a 'level' key indicating its severity.
        base_score: The initial score before deductions (defaults to 100).

    Returns:
        The calculated security score, an integer between 0 and 100.
    """
    score = base_score
    for finding in findings:
        level = finding.get(
            "level", "info"
        )  # Default to 'info' if level is not specified
        penalty = SEVERITY_SCORES.get(level, -5)  # Default penalty if level is unknown
        score += penalty
    return max(0, min(100, score))  # Ensure score is within 0-100 range


def _evaluate_legacy(metrics: dict) -> dict:
    """Evaluate metrics with a Python-based rule set, returning findings and a score.

    This function applies a predefined set of rules to the provided system
    metrics, generates a list of findings, and calculates an overall security score.
    It serves as the default evaluation mechanism if CLIPS is unavailable.

    Args:
        metrics: A dictionary of system security metrics, categorized.

    Returns:
        A dictionary representing the evaluation report, including 'score',
        'grade', 'summary', and a list of 'findings'.
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

    # Check if the number of running services exceeds the configured threshold.
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

    if "firewall" in metrics:
        profiles = metrics["firewall"].get("profiles", {})
        domain = profiles.get("domain")
        private = profiles.get("private")
        public = profiles.get("public")

        # all profiles off = critical
        if domain == "OFF" and private == "OFF" and public == "OFF":
            findings.append(
                {
                    "rule": "firewall_all_disabled",
                    "level": "critical",
                    "description": "All firewall profiles are disabled.",
                }
            )
        else:
            # individual profile warnings
            if public == "OFF":
                findings.append(
                    {
                        "rule": "firewall_public_disabled",
                        "level": "warning",
                        "description": "Public firewall profile is disabled.",
                    }
                )
            if domain == "OFF":
                findings.append(
                    {
                        "rule": "firewall_domain_disabled",
                        "level": "warning",
                        "description": "Domain firewall profile is disabled.",
                    }
                )
            if private == "OFF":
                findings.append(
                    {
                        "rule": "firewall_private_disabled",
                        "level": "warning",
                        "description": "Private firewall profile is disabled.",
                    }
                )
            # all profiles on = info
            if domain == "ON" and private == "ON" and public == "ON":
                findings.append(
                    {
                        "rule": "firewall_all_enabled",
                        "level": "info",
                        "description": "All firewall profiles are enabled.",
                    }
                )

    if "antivirus" in metrics:
        products = metrics["antivirus"].get("products", [])
        # none detected = critical
        if not products:
            findings.append(
                {
                    "rule": "antivirus_not_detected",
                    "level": "critical",
                    "description": "No antivirus products detected.",
                }
            )
        else:
            for p in products:
                # unknown state = warning
                if p.get("state") is None:
                    findings.append(
                        {
                            "rule": f"antivirus_{p['name']}_unknown",
                            "level": "warning",
                            "description": f"Antivirus product {p['name']} state unknown.",
                        }
                    )

    score = calculate_score(findings)
    # If any critical finding exists, override to Critical Risk
    if any(f.get("level") == "critical" for f in findings):
        grade = "Critical Risk"
    else:
        # Assign grade based on score thresholds
        if score >= 90:
            grade = "Excellent"
        elif score >= 80:
            grade = "Good"
        elif score >= 60:
            grade = "Fair"
        elif score >= 40:
            grade = "Poor"
        else:
            grade = "Critical Risk"

    return {
        "score": score,
        "grade": grade,
        "summary": (
            "No critical issues found."
            if not findings
            else "; ".join(f["description"] for f in findings)
        ),
        "findings": findings,
        "rules_fired": len(findings),
        "explanations": [],
    }


def _evaluate_clips(metrics: dict) -> dict:
    """Evaluate metrics with a CLIPS-based rule engine if available, otherwise fallback.

    This function attempts to use a CLIPS-based `SecurityExpertSystem` for
    evaluation. If CLIPS is not available or an error occurs during its
    execution, it falls back to the `_evaluate_legacy` Python-based engine.

    Args:
        metrics: A dictionary of system security metrics, categorized.

    Returns:
        A dictionary representing the evaluation report from CLIPS, or from
        the legacy evaluator if CLIPS fails. The report includes 'score',
        'grade', 'summary', and 'findings'.
    """
    try:
        from src.clips_evaluator import SecurityExpertSystem

        expert_system = SecurityExpertSystem()
        result = expert_system.evaluate(metrics)
        return result
    except Exception as e:  # Catches CLIPS import errors or runtime issues
        logger.error(
            f"Error using CLIPS evaluator: {e}. Falling back to legacy evaluator."
        )
        return _evaluate_legacy(metrics)


def evaluate(metrics: dict, use_clips: Optional[bool] = None) -> dict:
    """Evaluate system metrics, returning security findings, score, and grade.

    This is the main interface for security evaluation. It selects either the
    CLIPS expert system or the legacy Python-based engine based on availability
    and the `use_clips` parameter. The evaluation result is then enriched
    with a timestamp and the original metrics data.

    Args:
        metrics: A dictionary of system security metrics, categorized.
        use_clips: A boolean to explicitly request the CLIPS engine.
                   If None (default), CLIPS is used if available.
                   If True, CLIPS is used if available, otherwise legacy.
                   If False, legacy engine is used.

    Returns:
        A complete evaluation report dictionary, including 'score', 'grade',
        'summary', 'findings', 'timestamp', and the original 'metrics'.
    """
    # Determine whether to attempt using CLIPS.
    # If use_clips is explicitly set, respect that choice.
    # Otherwise, use CLIPS if it's available.
    should_use_clips = CLIPS_AVAILABLE
    if use_clips is not None:
        should_use_clips = use_clips

    # Run the appropriate evaluation engine.
    if should_use_clips and CLIPS_AVAILABLE:
        logger.info("Using CLIPS evaluation engine.")
        result = _evaluate_clips(metrics)
    else:
        if should_use_clips and not CLIPS_AVAILABLE:
            logger.warning(
                "CLIPS evaluation requested but CLIPS is not available. Falling back to legacy."
            )
        logger.info("Using legacy Python evaluation engine.")
        result = _evaluate_legacy(metrics)

    # Add timestamp and original metrics to the result for comprehensive logging.
    result["timestamp"] = datetime.now(timezone.utc).isoformat()
    result["metrics"] = metrics

    return result
