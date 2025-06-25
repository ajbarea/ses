"""Main entrypoint for the Security Evaluation Service. Defines REST endpoints for health,
metrics, and security evaluations."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.src.logging_config import setup_logging, get_logger
from pathlib import Path
import json
import os

from backend.src.rules import evaluate
import logging

from backend.src.scanner import (
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

Path("logs").mkdir(parents=True, exist_ok=True)  # Ensure logs directory exists

eval_logger = get_logger("evaluation")  # Logger for evaluation results
eval_handler = logging.FileHandler("logs/evaluation_log.jsonl")
eval_handler.setFormatter(logging.Formatter("%(message)s"))
eval_logger.addHandler(eval_handler)


app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
async def root():
    """Return a simple health check message."""
    logger.info("Health check endpoint called")
    return {"message": "Hello World"}


@app.get("/metrics")
async def metrics():
    """Return current system security metrics."""
    logger.info("Metrics endpoint called")
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
    """Collect and evaluate security metrics, then log and return the results."""
    logger.info("Evaluation endpoint called")
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
    eval_logger.info(json.dumps(result))  # Log evaluation result as JSONL
    return result


if __name__ == "__main__":
    import uvicorn

    # start the FastAPI app on 0.0.0.0:8000
    uvicorn.run(
        app, host="127.0.0.1", port=8000, log_level=os.getenv("LOG_LEVEL", "info")
    )
