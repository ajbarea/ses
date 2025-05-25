"""CLIPS-based rule engine for security metrics evaluation."""

import clips
from pathlib import Path
import io
from contextlib import redirect_stdout
from src.logging_config import get_logger

logger = get_logger(__name__)


class SecurityExpertSystem:
    """Manages a CLIPS environment to process system metrics and derive security findings."""

    def __init__(self, rules_dir=None):
        """Initialize CLIPS environment and load security rules.

        Args:
            rules_dir (str, optional): Path to directory containing CLIPS rule files.
                Defaults to 'clips_rules' in module directory.
        """
        self.env = clips.Environment()

        if rules_dir is None:
            rules_dir = Path(__file__).parent / "clips_rules"

        self.rules_dir = Path(rules_dir)
        self._load_templates()
        self._load_rules()

    def _load_templates(self):
        """Define CLIPS templates for security metrics and findings."""
        # Define templates for system metrics - one at a time to avoid syntax errors
        try:
            self.env.build(
                """(deftemplate patch-status
   (slot status)
   (multislot hotfixes))"""
            )

            self.env.build(
                """(deftemplate open-port
   (slot number))"""
            )

            self.env.build(
                """(deftemplate service
   (slot name)
   (slot state))"""
            )

            self.env.build(
                """(deftemplate firewall
   (slot domain)
   (slot private)
   (slot public))"""
            )

            self.env.build(
                """(deftemplate antivirus-product
   (slot name)
   (slot state))"""
            )

            self.env.build(
                """(deftemplate password-policy
   (slot min-password-length)
   (slot max-password-age))"""
            )

            self.env.build(
                """(deftemplate finding
   (slot rule-name)
   (slot level)
   (slot description)
   (multislot details)
   (slot recommendation (default "Review security configuration")))"""
            )

            self.env.build(
                """(deftemplate score
   (slot value)
   (slot type (default penalty)))"""
            )
        except clips.CLIPSError as e:
            logger.error(f"Error loading template: {e}")
            raise

    def _load_rules(self):
        """Load CLIPS rule files from the specified directory."""
        # Load all .clp files in the rules directory
        if not self.rules_dir.exists():
            logger.warning(f"Rules directory {self.rules_dir} does not exist.")
            return

        for rule_file in self.rules_dir.glob("*.clp"):
            try:
                self.env.load(str(rule_file))
                logger.info(f"Loaded rules from {rule_file}")
            except clips.CLIPSError as e:
                logger.error(f"Error loading {rule_file}: {e}")

    def _assert_patch_facts(self, patch_metrics):
        """Asserts CLIPS facts for patch metrics."""
        fact = f'(patch-status (status "{patch_metrics["status"]}")'
        if patch_metrics.get("hotfixes"):
            hotfixes = " ".join(f'"{h}"' for h in patch_metrics["hotfixes"])
            fact += f" (hotfixes {hotfixes})"
        fact += ")"
        self.env.assert_string(fact)

    def _assert_port_facts(self, port_metrics):
        """Asserts CLIPS facts for port metrics."""
        if "ports" in port_metrics:
            for port in port_metrics["ports"]:
                self.env.assert_string(f"(open-port (number {port}))")

    def _assert_service_facts(self, service_metrics):
        """Asserts CLIPS facts for service metrics."""
        if "services" in service_metrics:
            for service in service_metrics["services"]:
                self.env.assert_string(
                    f"(service (name \"{service['name']}\") (state \"{service['state']}\"))"
                )

    def _assert_firewall_facts(self, firewall_metrics):
        """Asserts CLIPS facts for firewall metrics."""
        if "profiles" in firewall_metrics:
            profiles = firewall_metrics["profiles"]
            self.env.assert_string(
                f"(firewall (domain \"{profiles.get('domain', 'UNKNOWN')}\") "
                f"(private \"{profiles.get('private', 'UNKNOWN')}\") "
                f"(public \"{profiles.get('public', 'UNKNOWN')}\"))"
            )

    def _assert_antivirus_facts(self, antivirus_metrics):
        """Asserts CLIPS facts for antivirus metrics."""
        if "products" in antivirus_metrics:
            for product in antivirus_metrics["products"]:
                raw = product.get("state")
                state = raw if raw is not None else "UNKNOWN"
                self.env.assert_string(
                    f"(antivirus-product (name \"{product['name']}\") (state {state}))"
                )

    def _assert_password_policy_facts(self, password_policy_metrics):
        """Asserts CLIPS facts for password policy metrics."""
        if "policy" in password_policy_metrics:
            policy = password_policy_metrics["policy"]
            self.env.assert_string(
                f"(password-policy (min-password-length {policy.get('min_password_length', 0)}) "
                f"(max-password-age {policy.get('max_password_age', 0)}))"
            )

    def convert_metrics_to_facts(self, metrics):
        """Assert CLIPS facts based on provided security metrics."""
        # Reset the environment for a new evaluation
        self.env.reset()

        if "patch" in metrics:
            self._assert_patch_facts(metrics["patch"])

        if "ports" in metrics:
            self._assert_port_facts(metrics["ports"])

        if "services" in metrics:
            self._assert_service_facts(metrics["services"])

        if "firewall" in metrics:
            self._assert_firewall_facts(metrics["firewall"])

        if "antivirus" in metrics:
            self._assert_antivirus_facts(metrics["antivirus"])

        if "password_policy" in metrics:
            self._assert_password_policy_facts(metrics["password_policy"])

    def run_evaluation(self):
        """Run the CLIPS inference engine and track rule activations."""
        self.rule_activations = []
        # Capture rule activations if watch supported
        captured = io.StringIO()
        with redirect_stdout(captured):
            try:
                self.env.watch("rules")
                watch_supported = True
            except (AttributeError, TypeError):
                watch_supported = False
            rules_fired = self.env.run()
        # Only process watch output if unwatch and parsing succeed
        if watch_supported:
            try:
                self.env.unwatch("rules")
                self._parse_watch_activations(captured.getvalue())
            except (AttributeError, TypeError):
                # Fallback to findings trace on error
                pass
        if not self.rule_activations:
            self._process_fallback(rules_fired)
        return rules_fired

    def _parse_watch_activations(self, output: str):
        """Extract activations from captured watch output."""
        for line in output.splitlines():
            if "FIRE" in line:
                parts = line.split()
                if len(parts) >= 3:
                    self.rule_activations.append(
                        {
                            "rule": parts[2],
                            "activation": line.strip(),
                        }
                    )

    def _process_fallback(self, rules_fired: int):
        """Fallback tracing when watch output is unavailable or empty."""
        # Generate trace from findings
        for finding in self.get_findings():
            self.rule_activations.append(
                {
                    "rule": finding.get("rule", "unknown"),
                    "activation": f"Rule activated: {finding.get('rule', 'unknown')} - {finding.get('description', '')}",
                }
            )
        if not self.rule_activations:
            self.rule_activations.append(
                {
                    "rule": "unknown",
                    "activation": f"{rules_fired} rules fired, but specific activations could not be traced.",
                }
            )

    def get_findings(self):
        """Extract 'finding' facts from the environment."""
        findings = []
        for finding in self.env.facts():
            # Only process finding facts
            if finding.template.name != "finding":
                continue

            finding_dict = {
                "rule": finding["rule-name"],
                "level": finding["level"],
                "description": finding["description"],
                "recommendation": finding["recommendation"],
            }

            if finding["details"]:
                finding_dict["details"] = list(finding["details"])

            findings.append(finding_dict)

        return findings

    def get_score(self, base_score=100):
        """Compute final security score from collected facts."""
        # Check if a score fact exists
        score = base_score
        for score_fact in self.env.facts():
            if score_fact.template.name == "score":
                if score_fact["type"] == "final":
                    return max(0, min(100, int(score_fact["value"])))
                elif score_fact["type"] == "penalty":
                    score += int(score_fact["value"])

        # If no final score was provided by the rules, calculate based on findings
        findings = self.get_findings()
        severity_scores = {
            "critical": -30,
            "warning": -10,
            "info": -5,
        }

        for finding in findings:
            level = finding.get("level", "info")
            penalty = severity_scores.get(level, -5)
            score += penalty

        return max(0, min(100, score))

    def get_rule_trace(self):
        """Return explanations of activated rules."""
        return self.rule_activations

    def evaluate(self, metrics):
        """Run the full CLIPS evaluation and return the results."""
        # Convert metrics to CLIPS facts
        self.convert_metrics_to_facts(metrics)

        # Run the inference engine
        rules_fired = self.run_evaluation()

        # Extract findings and calculate score
        findings = self.get_findings()
        score = self.get_score()

        # Determine grade based on score
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

        # Get rule explanations if available
        explanations = self.get_rule_trace()

        return {
            "score": score,
            "grade": grade,
            "summary": (
                "No critical issues found."
                if not findings
                else "; ".join(f["description"] for f in findings)
            ),
            "findings": findings,
            "rules_fired": rules_fired,
            "explanations": explanations,
        }
