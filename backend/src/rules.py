"""Security rule engine for evaluating Windows system security metrics.

Processes system metrics to generate security findings, calculate scores,
and determine an overall security grade for the system.
"""

from datetime import datetime, timezone
from typing import Optional

from .logging_config import get_logger
from .rule_descriptions import RULE_DESCRIPTIONS
from .scoring import (
    assign_grade,
    calculate_score,
    create_score_changes,
    DEFAULT_BASE_SCORE,
    format_score_impact_text,
    get_finding_score_impact,
)

logger = get_logger(__name__)

# Threshold for number of running services before triggering an alert
SERVICE_COUNT_THRESHOLD = 300

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


def _collect_password_findings(metrics):
    """Extract Windows password‐policy findings."""
    findings = []
    policy = metrics.get("password_policy", {}).get("policy", {})

    # minimum length
    m = policy.get("min_password_length", 0)
    if m < 8:
        key = "password_min_length_weak"
    elif m < 12:
        key = "password_min_length_acceptable"
    else:
        key = "password_min_length_strong"
    findings.append(
        {
            "rule": key,
            "level": RULE_DESCRIPTIONS[key]["level"],
            "description": f"{RULE_DESCRIPTIONS[key]['description']} Currently: {m}.",
        }
    )

    # complexity
    comp = policy.get("complexity", "disabled")
    key = (
        "password_complexity_disabled"
        if comp != "enabled"
        else "password_complexity_enabled"
    )
    findings.append(
        {
            "rule": key,
            "level": RULE_DESCRIPTIONS[key]["level"],
            "description": RULE_DESCRIPTIONS[key]["description"],
        }
    )

    # lockout threshold
    lt = policy.get("lockout_threshold", "not-defined")
    if lt == "not-defined":
        key = "account_lockout_not_defined"
    else:
        key = "account_lockout_defined"
    findings.append(
        {
            "rule": key,
            "level": RULE_DESCRIPTIONS[key]["level"],
            "description": RULE_DESCRIPTIONS[key]["description"],
        }
    )

    # history
    sz = policy.get("history_size", 0)
    if sz < 1:
        key = "password_history_disabled"
    else:
        key = "password_history_enabled"
    findings.append(
        {
            "rule": key,
            "level": RULE_DESCRIPTIONS[key]["level"],
            "description": f"{RULE_DESCRIPTIONS[key]['description']} Size: {sz}.",
        }
    )

    # max age
    ma = policy.get("max_password_age", "disabled")
    if ma == "disabled":
        key = "max_password_age_disabled"
    elif isinstance(ma, int) and ma > 365:
        key = "max_password_age_too_long"
    else:
        key = "max_password_age_enabled"
    findings.append(
        {
            "rule": key,
            "level": RULE_DESCRIPTIONS[key]["level"],
            "description": f"{RULE_DESCRIPTIONS[key]['description']} Days: {ma}.",
        }
    )

    return findings


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
    if "password_policy" in metrics:
        findings.extend(_collect_password_findings(metrics))

    score = calculate_score(findings, DEFAULT_BASE_SCORE)
    grade = assign_grade(score, findings)

    # Add score impact to findings and sort them
    for finding in findings:
        impact = get_finding_score_impact(finding)
        finding["score_impact"] = impact
        finding["score_text"] = format_score_impact_text(impact)

    # Sort findings: bonuses first, then neutral, then penalties (by severity)
    findings.sort(
        key=lambda f: (
            _score_type_to_order(f.get("score_impact", {}).get("type")),
            -1 * f.get("score_impact", {}).get("value", 0),
        )
    )

    # Generate score changes
    score_changes = create_score_changes(DEFAULT_BASE_SCORE, findings)

    # Organize findings by impact type
    positive_findings = [
        f for f in findings if f.get("score_impact", {}).get("type") == "bonus"
    ]
    neutral_findings = [
        f for f in findings if f.get("score_impact", {}).get("type") == "neutral"
    ]
    negative_findings = [
        f for f in findings if f.get("score_impact", {}).get("type") == "penalty"
    ]

    # Create impact summary
    impact_summary = ""
    if positive_findings:
        impact_summary += f"{len(positive_findings)} positive factors. "
    if negative_findings:
        impact_summary += f"{len(negative_findings)} items reducing your score. "
    if neutral_findings:
        impact_summary += f"{len(neutral_findings)} neutral findings. "

    summary = (
        "No critical issues found."
        if not findings
        else "; ".join(f["description"] for f in findings)
    )

    return {
        "score": score,
        "grade": grade,
        "summary": summary,
        "impact_summary": impact_summary,
        "findings": findings,
        "positive_findings": positive_findings,
        "negative_findings": negative_findings,
        "neutral_findings": neutral_findings,
        "rules_fired": len(findings),
        "explanations": [],
        "score_changes": score_changes,
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
        from .clips_evaluator import SecurityExpertSystem

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
                "CLIPS evaluation requested but CLIPS is not available. Falling back to legacy."
            )
        logger.info("Using legacy Python evaluation engine.")
        result = _evaluate_legacy(metrics)

    # Add metadata to result
    result["timestamp"] = datetime.now(timezone.utc).isoformat()
    result["metrics"] = metrics

    return result


def _score_type_to_order(score_type: str) -> int:
    if score_type == "bonus":
        return -1
    elif score_type == "neutral":
        return 0
    return 1
