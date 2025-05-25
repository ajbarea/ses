"""Security Evaluation Service (SES) REST API.

Provides endpoints for system security metric collection and evaluation.
Logs evaluation results in JSONL format for historical tracking.
"""

from fastapi import FastAPI
from src.logging_config import setup_logging, get_logger
from pathlib import Path
import json
import os

from src.rules import evaluate
import logging

from src.scanner import (
    get_antivirus_status,
    get_firewall_status,
    get_open_ports,
    get_password_policy,
    get_patch_status,
    get_running_services,
)

setup_logging(
    log_level=os.getenv("LOG_LEVEL", "INFO"),
    json_format=os.getenv("JSON_LOG_FORMAT", "False").lower() == "true",
    log_file=os.getenv("LOG_FILE"),
)
logger = get_logger(__name__)

# Ensure logs directory exists
Path("logs").mkdir(parents=True, exist_ok=True)

# Set up a separate logger to write evaluation JSONL
eval_logger = get_logger("evaluation")
eval_handler = logging.FileHandler("logs/evaluation_log.jsonl")
eval_handler.setFormatter(logging.Formatter("%(message)s"))
eval_logger.addHandler(eval_handler)


app = FastAPI()


@app.get("/")
async def root():
    """Simple health check endpoint.

    Returns:
        dict: Status message indicating service availability
    """
    logger.info("Health check endpoint called")
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
    logger.info("Starting security evaluation")
    # Append evaluation result as JSONL via dedicated evaluation logger
    eval_logger.info(json.dumps(result))
    return result
