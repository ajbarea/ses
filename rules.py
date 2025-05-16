"""Rules module for security evaluation.

Defines rules to evaluate system metrics and generate findings.
"""


def evaluate(metrics: dict) -> dict:
    """Evaluate security metrics and generate findings.

    Args:
        metrics (dict): Dictionary containing keys 'patch', 'ports', and 'services'.

    Returns:
        dict: A dictionary with key 'findings', a list of rule violations and their severity.
    """
    findings = []
    if metrics["patch"]["status"] != "up-to-date":
        findings.append({"rule": "patch_status", "level": "critical"})
    if len(metrics["ports"]["ports"]) > 0:
        findings.append({"rule": "open_ports", "level": "warning"})
    return {"findings": findings}
