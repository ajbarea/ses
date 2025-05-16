"""Main application for the Security Evaluation Service (SES).
Provides FastAPI endpoints to:
    * Fetch system metrics
    * Evaluate security based on predefined rules

Evaluation results are persisted to 'logs/evaluation_log.jsonl' (JSON Lines).
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
    """Health check endpoint returning a simple status message.

    Returns:
        Dict[str, str]: Verification message with key 'message'.
    """
    return {"message": "Hello World"}


@app.get("/metrics")
async def metrics():
    """Retrieve raw system metrics.

    This endpoint fetches various system security metrics such as:
        * Windows patch status
        * Listening TCP ports
        * Running services
        * Firewall profile states
        * Installed antivirus products
        * Local password policy

    Returns:
        Dict[str, Any]: A mapping of metric names to their values.
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
    """Execute security evaluation and log results.

    This endpoint:
        1. Collects current system metrics.
        2. Applies configured security rules.
        3. Appends the evaluation report as a JSON record to 'logs/evaluation_log.jsonl'.
        4. Returns the evaluation report including:
            - timestamp
            - score (0–100)
            - grade (e.g., 'Excellent', 'Good', 'Fair', 'Poor', 'Critical Risk')
            - summary of findings
            - detailed findings list
            - raw metrics

    Returns:
        Dict[str, Any]: Full security evaluation report.
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
