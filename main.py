"""Security Evaluation Service (SES) REST API.

Provides endpoints for system security metric collection and evaluation.
Logs evaluation results in JSONL format for historical tracking.
"""

from fastapi import FastAPI
import json
from scanner import (
    get_patch_status,
    get_open_ports,
    get_running_services,
    get_firewall_status,
    get_antivirus_status,
    get_password_policy,
)
from rules import evaluate

app = FastAPI()


@app.get("/")
async def root():
    """Simple health check endpoint.

    Returns:
        dict: Status message indicating service availability
    """
    return {"message": "Hello World"}


@app.get("/metrics")
async def metrics():
    """Collect current system security metrics.

    Gathers data about patches, ports, services, firewall,
    antivirus, and password policies.

    Returns:
        dict: Collected security metrics by category
    """
    return {
        "patch": get_patch_status(),
        "ports": get_open_ports(),
        "services": get_running_services(),
        "firewall": get_firewall_status(),
        "antivirus": get_antivirus_status(),
        "password_policy": get_password_policy(),
    }


@app.get("/evaluate")
async def evaluate_security():
    """Perform security evaluation and persist results.

    Collects metrics, evaluates security posture, and logs the report.
    Results are appended to logs/evaluation_log.jsonl in JSONL format.

    Returns:
        dict: Evaluation report containing score, grade, findings,
              and supporting details
    """
    metrics_data = {
        "patch": get_patch_status(),
        "ports": get_open_ports(),
        "services": get_running_services(),
        "firewall": get_firewall_status(),
        "antivirus": get_antivirus_status(),
        "password_policy": get_password_policy(),
    }
    result = evaluate(metrics_data)
    # log evaluation as one JSON record per line
    with open("logs/evaluation_log.jsonl", "a", encoding="utf-8") as logf:
        json.dump(result, logf)
        logf.write("\n")
    return result
