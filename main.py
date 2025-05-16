"""Main application module for the Security Evaluation Service.

Provides HTTP endpoints to retrieve system patch status, open ports, running services,
and to evaluate overall security metrics.
"""

from fastapi import FastAPI
from scanner import get_patch_status, get_open_ports, get_running_services
from rules import evaluate

app = FastAPI()


@app.get("/")
async def root():
    """Health check endpoint.

    Returns a simple greeting message to verify that the service is running.
    """
    return {"message": "Hello World"}


@app.get("/metrics")
async def metrics():
    """Retrieve system metrics.

    Returns:
        dict: A dictionary containing patch status, open ports, and running services.
    """
    return {
        "patch": get_patch_status(),
        "ports": get_open_ports(),
        "services": get_running_services(),
    }


@app.get("/evaluate")
async def evaluate_security():
    """Evaluate overall security metrics.

    Gathers system metrics and applies security rules to produce an evaluation report.

    Returns:
        dict: The result of the security evaluation.
    """
    metrics_data = {
        "patch": get_patch_status(),
        "ports": get_open_ports(),
        "services": get_running_services(),
    }
    return evaluate(metrics_data)
