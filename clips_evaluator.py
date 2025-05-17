"""CLIPS-based expert system for security evaluation.

Provides advanced rule engine capabilities using PyCLIPS to evaluate
system security metrics with sophisticated pattern matching and rule chaining.
"""

import clips
from pathlib import Path
import io
import sys


class SecurityExpertSystem:
    """Expert system for security evaluation using CLIPS.

    Uses PyCLIPS to load security rules, convert metrics to facts,
    run the inference engine, and extract evaluation results.
    """

    def __init__(self, rules_dir=None):
        """Initialize the CLIPS environment and load rules.

        Args:
            rules_dir (str, optional): Directory containing CLIPS rule files.
                Defaults to 'clips_rules' subdirectory within this module's directory.
        """
        self.env = clips.Environment()

        if rules_dir is None:
            rules_dir = Path(__file__).parent / "clips_rules"

        self.rules_dir = Path(rules_dir)
        self._load_templates()
        self._load_rules()

    def _load_templates(self):
        """Load CLIPS templates for security metrics."""
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
            print(f"Error loading template: {e}")
            raise

    def _load_rules(self):
        """Load CLIPS rule files from the rules directory."""
        # Load all .clp files in the rules directory
        if not self.rules_dir.exists():
            print(f"Warning: Rules directory {self.rules_dir} does not exist.")
            return

        for rule_file in self.rules_dir.glob("*.clp"):
            try:
                self.env.load(str(rule_file))
                print(f"Loaded rules from {rule_file}")
            except clips.CLIPSError as e:
                print(f"Error loading {rule_file}: {e}")

    def convert_metrics_to_facts(self, metrics):
        """Convert Python metrics dictionary to CLIPS facts.

        Args:
            metrics (dict): System metrics data.
        """
        # Reset the environment for a new evaluation
        self.env.reset()

        # Convert patch metrics
        if "patch" in metrics:
            patch = metrics["patch"]
            fact = f'(patch-status (status "{patch["status"]}")'
            if patch.get("hotfixes"):
                hotfixes = " ".join(f'"{h}"' for h in patch["hotfixes"])
                fact += f" (hotfixes {hotfixes})"
            fact += ")"
            self.env.assert_string(fact)

        # Convert port metrics
        if "ports" in metrics and "ports" in metrics["ports"]:
            for port in metrics["ports"]["ports"]:
                self.env.assert_string(f"(open-port (number {port}))")

        # Convert service metrics
        if "services" in metrics and "services" in metrics["services"]:
            for service in metrics["services"]["services"]:
                self.env.assert_string(
                    f"(service (name \"{service['name']}\") (state \"{service['state']}\"))"
                )

        # Convert firewall metrics
        if "firewall" in metrics and "profiles" in metrics["firewall"]:
            profiles = metrics["firewall"]["profiles"]
            self.env.assert_string(
                f"(firewall (domain \"{profiles.get('domain', 'UNKNOWN')}\") "
                f"(private \"{profiles.get('private', 'UNKNOWN')}\") "
                f"(public \"{profiles.get('public', 'UNKNOWN')}\"))"
            )

        # Convert antivirus metrics
        if "antivirus" in metrics and "products" in metrics["antivirus"]:
            for product in metrics["antivirus"]["products"]:
                state = product.get("state", "UNKNOWN")
                self.env.assert_string(
                    f"(antivirus-product (name \"{product['name']}\") (state {state}))"
                )

        # Convert password policy metrics
        if "password_policy" in metrics and "policy" in metrics["password_policy"]:
            policy = metrics["password_policy"]["policy"]
            self.env.assert_string(
                f"(password-policy (min-password-length {policy.get('min_password_length', 0)}) "
                f"(max-password-age {policy.get('max_password_age', 0)}))"
            )

    def run_evaluation(self):
        """Run the CLIPS inference engine and capture rule activations.

        Returns:
            int: Number of rules that were fired.
        """
        # Set up rule tracking
        self.rule_activations = []

        # Check facts before evaluation
        before_facts = set(str(fact) for fact in self.env.facts())

        try:
            # Try to use watch functionality if available
            original_stdout = sys.stdout
            captured_output = io.StringIO()
            sys.stdout = captured_output

            try:
                # This may raise AttributeError if watch is not supported
                self.env.watch("rules")
                watch_supported = True
            except (AttributeError, TypeError):
                watch_supported = False

            # Run the inference engine
            rules_fired = self.env.run()

            if watch_supported:
                try:
                    # Disable watching if it was enabled
                    self.env.unwatch("rules")

                    # Process the captured output to extract rule activations
                    output = captured_output.getvalue()
                    for line in output.splitlines():
                        if "FIRE" in line:
                            # Extract rule name from activation line
                            parts = line.split()
                            if len(parts) >= 3:
                                rule_name = parts[2]
                                self.rule_activations.append(
                                    {"rule": rule_name, "activation": line.strip()}
                                )
                except (AttributeError, TypeError):
                    pass
        finally:
            # Always restore stdout if we changed it
            if "original_stdout" in locals():
                sys.stdout = original_stdout

        # If watch wasn't supported, use facts comparison as fallback mechanism
        if not self.rule_activations:
            # Capture facts after running
            after_facts = set(str(fact) for fact in self.env.facts())

            # New facts (especially findings) can help trace rules
            new_facts = after_facts - before_facts

            # Get findings and create basic rule trace
            for finding in self.get_findings():
                self.rule_activations.append(
                    {
                        "rule": finding.get("rule", "unknown"),
                        "activation": f"Rule activated: {finding.get('rule', 'unknown')} - {finding.get('description', '')}",
                    }
                )

            if not self.rule_activations:
                # If no findings, just report that rules were fired
                self.rule_activations.append(
                    {
                        "rule": "unknown",
                        "activation": f"{rules_fired} rules fired, but specific activations could not be traced.",
                    }
                )

        return rules_fired

    def get_findings(self):
        """Extract findings from CLIPS facts.

        Returns:
            list: List of finding dictionaries.
        """
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
        """Calculate security score based on CLIPS facts.

        Args:
            base_score (int, optional): Initial score before penalties. Defaults to 100.

        Returns:
            int: Final security score, clamped between 0 and 100.
        """
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
        """Get the explanation trace of rule activations.

        Returns:
            list: Rule activation sequence with explanations.
        """
        return self.rule_activations

    def evaluate(self, metrics):
        """Perform full security evaluation using CLIPS.

        Args:
            metrics (dict): System security metrics.

        Returns:
            dict: Evaluation results with score, findings, and explanations.
        """
        # Convert metrics to CLIPS facts
        self.convert_metrics_to_facts(metrics)

        # Run the inference engine
        rules_fired = self.run_evaluation()

        # Extract findings and calculate score
        findings = self.get_findings()
        score = self.get_score()

        # Determine grade based on score
        grade = (
            "Excellent"
            if score >= 90
            else (
                "Good"
                if score >= 80
                else (
                    "Fair"
                    if score >= 60
                    else "Poor" if score >= 40 else "Critical Risk"
                )
            )
        )

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
