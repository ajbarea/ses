"""Provide a CLIPS-based expert system for Windows security evaluation."""

import clips
from pathlib import Path
import io
from contextlib import redirect_stdout
from src.logging_config import get_logger

logger = get_logger(__name__)


class SecurityExpertSystem:
    """Manage a CLIPS environment to evaluate system security metrics."""

    def __init__(self, rules_dir=None):
        """Initialize CLIPS environment and load rule templates and files."""
        self.env = clips.Environment()

        if rules_dir is None:
            rules_dir = Path(__file__).parent / "clips_rules"

        self.rules_dir = Path(rules_dir)
        self._load_templates()
        self._load_rules()

    def _load_templates(self):
        """Define the CLIPS deftemplates for metrics and findings."""
        try:
            # Patch status template for Windows update information
            self.env.build(
                """(deftemplate patch-status
   (slot status)
   (multislot hotfixes))"""
            )

            # Open port template for network port analysis
            self.env.build(
                """(deftemplate open-port
   (slot number))"""
            )

            # Service template for Windows service analysis
            self.env.build(
                """(deftemplate service
   (slot name)
   (slot state))"""
            )

            # Firewall template for Windows Firewall profile analysis
            self.env.build(
                """(deftemplate firewall
   (slot domain)
   (slot private)
   (slot public))"""
            )

            # Antivirus product template for individual AV solutions
            self.env.build(
                """(deftemplate antivirus-product
   (slot name)
   (slot state))"""
            )

            # Antivirus info template for overall antivirus status
            self.env.build(
                """(deftemplate antivirus-info
   (slot status (default "unknown"))
   (slot definitions (default "unknown"))
   (slot real-time-protection (default "unknown")))"""
            )

            # Password policy template for password settings analysis
            self.env.build(
                """(deftemplate password-policy
   (slot min-password-length)
   (slot max-password-age))"""
            )

            # Finding template for security findings/alerts
            self.env.build(
                """(deftemplate finding
   (slot rule-name)
   (slot level)
   (slot description)
   (multislot details)
   (slot recommendation (default "Review security configuration")))"""
            )

            # Score template for security score calculations
            self.env.build(
                """(deftemplate score
   (slot value)
   (slot type (default penalty)))"""
            )
        except clips.CLIPSError as e:
            logger.error(f"Error loading template: {e}")
            raise

    def _load_rules(self):
        """Load all .clp rule files from the configured rules directory."""
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
        """Assert a patch-status fact from the given metrics dict."""
        fact = f'(patch-status (status "{patch_metrics["status"]}")'
        if patch_metrics.get("hotfixes"):
            hotfixes = " ".join(f'"{h}"' for h in patch_metrics["hotfixes"])
            fact += f" (hotfixes {hotfixes})"
        fact += ")"
        self.env.assert_string(fact)

    def _assert_port_facts(self, port_metrics):
        """Assert open-port facts for each port in port_metrics['ports']."""
        if "ports" in port_metrics:
            for port in port_metrics["ports"]:
                self.env.assert_string(f"(open-port (number {port}))")

    def _assert_service_facts(self, service_metrics):
        """Assert service facts from service_metrics['services'] list."""
        if "services" in service_metrics:
            for service in service_metrics["services"]:
                self.env.assert_string(
                    f"(service (name \"{service['name']}\") (state \"{service['state']}\"))"
                )

    def _assert_firewall_facts(self, firewall_metrics):
        """Assert a firewall-profile fact using provided profiles dict."""
        if "profiles" in firewall_metrics:
            profiles = firewall_metrics["profiles"]
            self.env.assert_string(
                f"(firewall (domain \"{profiles.get('domain', 'UNKNOWN')}\") "
                f"(private \"{profiles.get('private', 'UNKNOWN')}\") "
                f"(public \"{profiles.get('public', 'UNKNOWN')}\"))"
            )

    def _assert_antivirus_facts(self, antivirus_metrics):
        """Assert antivirus-product facts and derive overall antivirus-info."""
        if "products" in antivirus_metrics:
            products = antivirus_metrics["products"]

            # Assert each product
            for product in products:
                raw = product.get("state")
                state = raw if raw is not None else "UNKNOWN"
                self.env.assert_string(
                    f"(antivirus-product (name \"{product['name']}\") (state {state}))"
                )

            if products:
                # Determine enabled vs. disabled counts
                # values < 397312 indicate disabled/risk per Windows SCC
                disabled_count = sum(
                    1
                    for p in products
                    if p.get("state") is None
                    or (isinstance(p.get("state"), int) and p["state"] < 397312)
                )
                # overall status
                if disabled_count == len(products):
                    status = "disabled"
                elif disabled_count > 0:
                    status = "partial"
                else:
                    status = "enabled"
                # definitions out-of-date if any state is undefined
                definitions = (
                    "out-of-date"
                    if any(p.get("state") is None for p in products)
                    else "up-to-date"
                )
                # real-time protection follows enabled status
                rtp_status = "enabled" if status == "enabled" else "disabled"
                self.env.assert_string(
                    f'(antivirus-info (status "{status}") '
                    f'(definitions "{definitions}") '
                    f'(real-time-protection "{rtp_status}"))'
                )
        else:
            # No products detected - disabled status
            self.env.assert_string(
                "(antivirus-info "
                '(status "disabled") '
                '(definitions "up-to-date") '
                '(real-time-protection "disabled")'
                ")"
            )

    def _assert_password_policy_facts(self, password_policy_metrics):
        """Assert password-policy fact with minimum length and maximum age."""
        if "policy" in password_policy_metrics:
            policy = password_policy_metrics["policy"]
            self.env.assert_string(
                f"(password-policy (min-password-length {policy.get('min_password_length', 0)}) "
                f"(max-password-age {policy.get('max_password_age', 0)}))"
            )

    def convert_metrics_to_facts(self, metrics):
        """Reset environment and assert facts for each metrics category."""
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
            av_data = metrics["antivirus"]
            products = av_data.get("products", [])

            # Assert individual product facts
            for product in products:
                name = product.get("name")
                state = product.get("state")

                # Handle null/None state
                if state is None:
                    state = "UNKNOWN"

                self.env.assert_string(
                    f'(antivirus-product (name "{name}") (state {state}))'
                )

            # Determine overall antivirus status
            if not products:
                # No products detected - disabled status
                self.env.assert_string(
                    "(antivirus-info "
                    '(status "disabled") '
                    '(definitions "up-to-date") '
                    '(real-time-protection "disabled")'
                    ")"
                )
            else:
                # Process products to determine overall status
                # values < 397312 indicate disabled/risk per Windows SCC
                disabled_count = sum(
                    1
                    for p in products
                    if p.get("state") is None
                    or (isinstance(p.get("state"), int) and p["state"] < 397312)
                )
                # overall status
                if disabled_count == len(products):
                    status = "disabled"
                elif disabled_count > 0:
                    status = "partial"
                else:
                    status = "enabled"
                # definitions out-of-date if any state is undefined
                definitions = (
                    "out-of-date"
                    if any(p.get("state") is None for p in products)
                    else "up-to-date"
                )
                # real-time protection follows enabled status
                rtp_status = "enabled" if status == "enabled" else "disabled"
                self.env.assert_string(
                    f'(antivirus-info (status "{status}") '
                    f'(definitions "{definitions}") '
                    f'(real-time-protection "{rtp_status}"))'
                )

        if "password_policy" in metrics:
            self._assert_password_policy_facts(metrics["password_policy"])

    def run_evaluation(self):
        """Run the CLIPS engine, capture and parse rule activations."""
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

        # Process watch output if supported and unwatch succeeds
        if watch_supported:
            try:
                self.env.unwatch("rules")
                self._parse_watch_activations(captured.getvalue())
            except (AttributeError, TypeError):
                # Fallback to findings trace if unwatch fails
                pass

        # If no activations were captured, use fallback method
        if not self.rule_activations:
            self._process_fallback(rules_fired)

        return rules_fired

    def _parse_watch_activations(self, output: str):
        """Extract fired rule names from CLIPS watch output."""
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
        """Fallback: derive activations from findings when tracing is unavailable."""
        # Use findings as a source of rule activation info when tracing not available
        for finding in self.get_findings():
            self.rule_activations.append(
                {
                    "rule": finding.get("rule", "unknown"),
                    "activation": f"Rule activated: {finding.get('rule', 'unknown')} - {finding.get('description', '')}",
                }
            )
        # Add placeholder entry if no findings were generated but rules fired
        if not self.rule_activations:
            self.rule_activations.append(
                {
                    "rule": "unknown",
                    "activation": f"{rules_fired} rules fired, but specific activations could not be traced.",
                }
            )

    def get_findings(self):
        """Return a list of finding dicts with computed score impacts."""
        findings = []
        score_facts = {}

        # First, collect all score facts to associate with findings
        for fact in self.env.facts():
            if fact.template.name == "score":
                # Get rule name from asserted finding if available
                rule_context = getattr(fact, "rule_context", None)
                if rule_context:
                    score_facts[rule_context] = {
                        "value": int(fact["value"]),
                        "type": fact["type"],
                    }

        for finding in self.env.facts():
            # Only process finding facts
            if finding.template.name != "finding":
                continue

            rule_name = finding["rule-name"]
            finding_dict = {
                "rule": rule_name,
                "level": finding["level"],
                "description": finding["description"],
                "recommendation": finding["recommendation"],
            }

            # Add score impact information if available
            score_impact = None
            for fact in self.env.facts():
                if (
                    fact.template.name == "score"
                    and hasattr(fact, "related_finding")
                    and fact.related_finding == rule_name
                ):
                    score_impact = {"value": int(fact["value"]), "type": fact["type"]}
                    break

            # Try to find by rule name if not found by direct relation
            if not score_impact and rule_name in score_facts:
                score_impact = score_facts[rule_name]

            # If still not found, do general lookup by matching rule activation pattern
            if not score_impact:
                for activation in self.rule_activations:
                    if activation.get("rule") and rule_name in activation.get("rule"):
                        # Look for scores asserted during this activation
                        for fact in self.env.facts():
                            if (
                                fact.template.name == "score"
                                and hasattr(fact, "activation")
                                and fact.activation == activation.get("activation")
                            ):
                                score_impact = {
                                    "value": int(fact["value"]),
                                    "type": fact["type"],
                                }
                                break

            # Default if we can't find the specific score impact
            if not score_impact:
                # Assign default score impact based on finding level
                if finding["level"] == "info":
                    score_impact = {"value": 0, "type": "neutral"}
                elif finding["level"] == "warning":
                    score_impact = {"value": -10, "type": "penalty"}
                elif finding["level"] == "critical":
                    score_impact = {"value": -30, "type": "penalty"}

            # Add score impact to finding dict
            if score_impact:
                finding_dict["score_impact"] = score_impact

                # Add a formatted string for display
                if score_impact["type"] == "penalty":
                    finding_dict["score_text"] = f"-{abs(score_impact['value'])} points"
                elif score_impact["type"] == "bonus":
                    finding_dict["score_text"] = f"+{score_impact['value']} points"
                else:
                    finding_dict["score_text"] = "0 points (neutral)"

            if finding["details"]:
                finding_dict["details"] = list(finding["details"])

            findings.append(finding_dict)

        # Sort findings by score impact (bonuses first, then neutral, then penalties)
        findings.sort(
            key=lambda f: (
                (
                    -1
                    if f.get("score_impact", {}).get("type") == "bonus"
                    else 0 if f.get("score_impact", {}).get("type") == "neutral" else 1
                ),
                -1 * f.get("score_impact", {}).get("value", 0),
            )
        )

        return findings

    def get_score(self, base_score=100):
        """Compute and return the final security score (0–100)."""
        # Check for score facts
        score = base_score
        score_details = []

        for score_fact in self.env.facts():
            if score_fact.template.name == "score":
                value = int(score_fact["value"])

                if score_fact["type"] == "final":
                    # Final score overrides all other calculations
                    return max(0, min(100, value))
                elif score_fact["type"] == "penalty":
                    score += value
                    score_details.append(
                        {
                            "type": "penalty",
                            "value": value,
                            "description": getattr(
                                score_fact, "description", "Penalty"
                            ),
                        }
                    )
                elif score_fact["type"] == "bonus":
                    score += value
                    score_details.append(
                        {
                            "type": "bonus",
                            "value": value,
                            "description": getattr(score_fact, "description", "Bonus"),
                        }
                    )

        # Ensure score is in valid range
        return max(0, min(100, score))

    def get_rule_trace(self):
        """Return the list of recorded rule activation events."""
        return self.rule_activations

    def evaluate(self, metrics):
        """Run a full evaluation: assert facts, infer, and summarize results.

        Returns a dict with score, grade, findings, and impact summary.
        """
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

        # Organize findings by impact
        positive_findings = [
            f for f in findings if f.get("score_impact", {}).get("type") == "bonus"
        ]
        neutral_findings = [
            f for f in findings if f.get("score_impact", {}).get("type") == "neutral"
        ]
        negative_findings = [
            f for f in findings if f.get("score_impact", {}).get("type") == "penalty"
        ]

        # Create summary that explains score impacts
        impact_summary = ""
        if positive_findings:
            impact_summary += f"{len(positive_findings)} positive factors. "
        if negative_findings:
            impact_summary += f"{len(negative_findings)} items reducing your score. "
        if neutral_findings:
            impact_summary += f"{len(neutral_findings)} neutral findings. "

        return {
            "score": score,
            "grade": grade,
            "summary": (
                "No critical issues found."
                if not findings
                else "; ".join(f["description"] for f in findings)
            ),
            "impact_summary": impact_summary,
            "findings": findings,
            "positive_findings": positive_findings,
            "negative_findings": negative_findings,
            "neutral_findings": neutral_findings,
            "rules_fired": rules_fired,
            "explanations": explanations,
        }
