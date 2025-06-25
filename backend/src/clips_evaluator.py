"""Module for a Windows security expert system using CLIPS to evaluate security metrics."""

import io
from contextlib import redirect_stdout
from pathlib import Path

import clips

from .logging_config import get_logger
from .scoring import (
    DEFAULT_BASE_SCORE,
    apply_score_impacts,
    assign_grade,
    create_score_changes,
    format_score_impact_text,
    get_clips_finding_impact,
)

logger = get_logger(__name__)


class SecurityExpertSystem:
    """Expert system that evaluates Windows security metrics using CLIPS."""

    def __init__(self, rules_dir=None):
        """
        Initialize the expert system and load rule files.

        Args:
            rules_dir (str or Path, optional): Directory containing CLIPS rule files.
                Defaults to the "clips_rules" subdirectory relative to this file.
        """
        self.env = clips.Environment()

        if rules_dir is None:
            rules_dir = Path(__file__).parent / "clips_rules"

        self.rules_dir = Path(rules_dir)
        self._load_templates()
        self._load_rules()

    def _load_templates(self):
        """
        Define CLIPS templates for security metrics and findings.

        Raises:
            clips.CLIPSError: If a template fails to build.
        """
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
                """(deftemplate antivirus-info
   (slot status (default "unknown"))
   (slot definitions (default "unknown"))
   (slot real-time-protection (default "unknown")))"""
            )
            self.env.build(
                """(deftemplate password-policy
   (slot min-length (type INTEGER) (default 0))
   (slot complexity (default "disabled"))
   (slot lockout-threshold (type INTEGER SYMBOL) (default not-defined))
   (slot history-size (type INTEGER) (default 0))
   (slot max-age (type INTEGER SYMBOL) (default disabled)))"""
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
   (slot rule-name)
   (slot value)
   (slot type (default penalty)))"""
            )
        except clips.CLIPSError as e:
            logger.error(f"Error loading template: {e}")
            raise

    def _determine_antivirus_status(self, products):
        """
        Determine overall antivirus status from product states.

        Args:
            products (list): List of antivirus product dictionaries.

        Returns:
            dict: Antivirus status with keys 'status', 'definitions', and 'rtp_status'.
        """
        if not products:
            return {
                "status": "disabled",
                "definitions": "up-to-date",
                "rtp_status": "disabled",
            }

        disabled_count = sum(
            1
            for p in products
            if p.get("state") is None
            or (isinstance(p.get("state"), int) and p["state"] < 262144)
            or (isinstance(p.get("state"), str) and p["state"] == "UNKNOWN")
        )

        if disabled_count == len(products):
            status = "disabled"
        elif disabled_count > 0:
            status = "partial"
        else:
            status = "enabled"

        definitions = (
            "out-of-date"
            if any(p.get("state") is None for p in products)
            else "up-to-date"
        )
        rtp_status = "enabled" if status == "enabled" else "disabled"

        return {
            "status": status,
            "definitions": definitions,
            "rtp_status": rtp_status,
        }

    def _load_rules(self):
        """
        Load all CLIPS rule files from the specified rules directory.
        """
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
        """
        Assert a CLIPS fact for patch metrics.

        Args:
            patch_metrics (dict): Contains patch status and hotfixes.
        """
        fact = f'(patch-status (status "{patch_metrics["status"]}")'
        if patch_metrics.get("hotfixes"):
            hotfixes = " ".join(f'"{h}"' for h in patch_metrics["hotfixes"])
            fact += f" (hotfixes {hotfixes})"
        fact += ")"
        self.env.assert_string(fact)

    def _assert_port_facts(self, port_metrics):
        """
        Assert CLIPS facts for each open port.

        Args:
            port_metrics (dict): Dictionary with a list of open ports.
        """
        if "ports" in port_metrics:
            for port in port_metrics["ports"]:
                self.env.assert_string(f"(open-port (number {port}))")

    def _assert_service_facts(self, service_metrics):
        """
        Assert CLIPS facts for services.

        Args:
            service_metrics (dict): Contains a list of services with names and states.
        """
        if "services" in service_metrics:
            for service in service_metrics["services"]:
                self.env.assert_string(
                    f"(service (name \"{service['name']}\") (state \"{service['state']}\"))"
                )

    def _assert_firewall_facts(self, firewall_metrics):
        """
        Assert a CLIPS fact for firewall profiles.

        Args:
            firewall_metrics (dict): Contains firewall profile metrics.
        """
        if "profiles" in firewall_metrics:
            profiles = firewall_metrics["profiles"]
            self.env.assert_string(
                f"(firewall (domain \"{profiles.get('domain', 'UNKNOWN')}\") "
                f"(private \"{profiles.get('private', 'UNKNOWN')}\") "
                f"(public \"{profiles.get('public', 'UNKNOWN')}\"))"
            )

    def _assert_antivirus_facts(self, antivirus_metrics):
        """
        Assert CLIPS facts for antivirus products and overall antivirus status.

        Args:
            antivirus_metrics (dict): Contains antivirus product details.
        """
        if "products" in antivirus_metrics:
            products = antivirus_metrics["products"]

            for product in products:
                raw = product.get("state")
                state = raw if raw is not None else "UNKNOWN"
                self.env.assert_string(
                    f"(antivirus-product (name \"{product['name']}\") (state {state}))"
                )

            av_status_info = self._determine_antivirus_status(products)
            self.env.assert_string(
                f"(antivirus-info (status \"{av_status_info['status']}\") "
                f"(definitions \"{av_status_info['definitions']}\") "
                f"(real-time-protection \"{av_status_info['rtp_status']}\"))"
            )
        else:
            av_status_info = self._determine_antivirus_status([])
            self.env.assert_string(
                f"(antivirus-info (status \"{av_status_info['status']}\") "
                f"(definitions \"{av_status_info['definitions']}\") "
                f"(real-time-protection \"{av_status_info['rtp_status']}\"))"
            )

    def _assert_password_policy_facts(self, password_policy_metrics):
        """
        Assert a CLIPS fact for password policy settings.

        Args:
            password_policy_metrics (dict): Contains password policy configurations.
        """
        if "policy" in password_policy_metrics:
            policy = password_policy_metrics["policy"]
            fact_string = "(password-policy "
            fact_string += f"(min-length {policy.get('min_password_length', 0)}) "
            fact_string += f"(complexity \"{policy.get('complexity', 'disabled')}\") "
            lockout_threshold_val = policy.get("lockout_threshold", "not-defined")
            fact_string += f"(lockout-threshold {lockout_threshold_val}) "
            fact_string += f"(history-size {policy.get('history_size', 0)}) "
            max_age_val = policy.get("max_password_age", "disabled")
            fact_string += f"(max-age {max_age_val})"
            fact_string += ")"
            self.env.assert_string(fact_string)

    def convert_metrics_to_facts(self, metrics):
        """
        Reset the CLIPS environment and assert metrics as facts.

        Args:
            metrics (dict): Security metrics categorized by type.
        """
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
            for product in products:
                name = product.get("name")
                state = product.get("state") or "UNKNOWN"
                self.env.assert_string(
                    f'(antivirus-product (name "{name}") (state {state}))'
                )
            av_status_info = self._determine_antivirus_status(products)
            self.env.assert_string(
                f"(antivirus-info (status \"{av_status_info['status']}\") "
                f"(definitions \"{av_status_info['definitions']}\") "
                f"(real-time-protection \"{av_status_info['rtp_status']}\"))"
            )

        if "password_policy" in metrics:
            self._assert_password_policy_facts(metrics["password_policy"])

    def run_evaluation(self):
        """
        Run the inference engine and capture fired rules.

        Returns:
            int: Number of rules that fired.
        """
        self.rule_activations = []
        captured = io.StringIO()
        with redirect_stdout(captured):
            try:
                self.env.watch("rules")
                watch_supported = True
            except (AttributeError, TypeError):
                watch_supported = False
            rules_fired = self.env.run()

        if watch_supported:
            try:
                self.env.unwatch("rules")
                self._parse_watch_activations(captured.getvalue())
            except (AttributeError, TypeError):
                pass

        if not self.rule_activations:
            self._process_fallback(rules_fired)

        return rules_fired

    def _parse_watch_activations(self, output: str):
        """
        Parse rule activations from CLIPS watch output.

        Args:
            output (str): Output from the watch command.
        """
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
        """
        Construct rule activation info from findings as a fallback.

        Args:
            rules_fired (int): Number of rules fired.
        """
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

    def _get_score_impact_for_finding(self, finding_dict, score_facts, rule_name):
        """
        Determine the score impact for a finding using multiple matching strategies.

        Args:
            finding_dict (dict): Details of the finding.
            score_facts (dict): Mapping of rule names to score impacts.
            rule_name (str): Name of the rule.

        Returns:
            dict: Score impact with 'value' and 'type', or a default if not found.
        """
        direct = self._direct_score_impact(rule_name)
        if direct:
            return direct

        if rule_name in score_facts:
            return score_facts[rule_name]

        activation = self._activation_score_impact(rule_name)
        if activation:
            return activation

        return get_clips_finding_impact(finding_dict)

    def _direct_score_impact(self, rule_name):
        """
        Retrieve score impact directly linked to a rule.

        Args:
            rule_name (str): The rule name.

        Returns:
            dict or None: Score impact if a matching fact is found; otherwise, None.
        """
        for fact in self.env.facts():
            if (
                fact.template.name == "score"
                and getattr(fact, "related_finding", None) == rule_name
            ):
                return {"value": int(fact["value"]), "type": fact["type"]}
        return None

    def _activation_score_impact(self, rule_name):
        """
        Retrieve score impact based on activation logs for a rule.

        Args:
            rule_name (str): The rule name.

        Returns:
            dict or None: Score impact if found; otherwise, None.
        """
        for activation in self.rule_activations:
            if rule_name not in activation.get("rule", ""):
                continue

            act_id = activation.get("activation")
            for fact in self.env.facts():
                if (
                    fact.template.name == "score"
                    and getattr(fact, "activation", None) == act_id
                ):
                    return {"value": int(fact["value"]), "type": fact["type"]}
        return None

    def _sort_findings(self, findings):
        """
        Sort findings based on impact: bonuses first, then neutral, then penalties.

        Args:
            findings (list): List of finding dictionaries.

        Returns:
            list: Sorted findings.
        """

        def _get_type_order(impact_type):
            if impact_type == "bonus":
                return -1
            elif impact_type == "neutral":
                return 0
            return 1

        findings.sort(
            key=lambda f: (
                _get_type_order(f.get("score_impact", {}).get("type")),
                -f.get("score_impact", {}).get("value", 0),
            )
        )
        return findings

    def get_findings(self):
        """
        Retrieve and enrich security findings with score impacts.

        Returns:
            list: Sorted list of finding dictionaries.
        """
        findings = []
        score_facts = {}

        for fact in self.env.facts():
            if fact.template.name == "score":
                rn = fact["rule-name"]
                score_facts[rn] = {
                    "value": int(fact["value"]),
                    "type": fact["type"],
                }

        for fact in self.env.facts():
            if fact.template.name != "finding":
                continue

            rule_name = fact["rule-name"]
            finding_dict = {
                "rule": rule_name,
                "level": fact["level"],
                "description": fact["description"],
                "recommendation": fact["recommendation"],
            }

            score_impact = self._get_score_impact_for_finding(
                finding_dict, score_facts, rule_name
            )

            if score_impact:
                finding_dict["score_impact"] = score_impact
                finding_dict["score_text"] = format_score_impact_text(score_impact)

            if fact["details"]:
                finding_dict["details"] = list(fact["details"])

            findings.append(finding_dict)

        return self._sort_findings(findings)

    def get_score(self, base_score=DEFAULT_BASE_SCORE):
        """
        Compute the final security score from CLIPS facts.

        Args:
            base_score (int): The starting score.

        Returns:
            int: Final score clamped between 0 and 100.
        """
        impacts = []
        final_score = None

        for fact in self.env.facts():
            if fact.template.name == "score":
                if fact["type"] == "final":
                    final_score = int(fact["value"])
                    break
                impacts.append({"type": fact["type"], "value": int(fact["value"])})

        if final_score is not None:
            return max(0, min(100, final_score))

        # If no explicit score facts, calculate from findings
        if not impacts:
            from src.scoring import calculate_score

            findings = []
            for fact in self.env.facts():
                if fact.template.name == "finding":
                    findings.append({"level": fact["level"]})
            return calculate_score(findings, base_score)

        return apply_score_impacts(base_score, impacts)

    def get_rule_trace(self):
        """
        Return the list of recorded rule activation events.

        Returns:
            list: Rule activation event dictionaries.
        """
        return self.rule_activations

    def evaluate(self, metrics):
        """
        Evaluate security metrics and generate a detailed report.

        Args:
            metrics (dict): Security metrics organized by category.

        Returns:
            dict: Evaluation report including score, grade, findings, and explanations.
        """
        self.convert_metrics_to_facts(metrics)
        rules_fired = self.run_evaluation()
        findings = self.get_findings()
        score = self.get_score()
        grade = assign_grade(score, findings)
        explanations = self.get_rule_trace()
        score_changes = create_score_changes(DEFAULT_BASE_SCORE, findings)

        positive_findings = [
            f for f in findings if f.get("score_impact", {}).get("type") == "bonus"
        ]
        neutral_findings = [
            f for f in findings if f.get("score_impact", {}).get("type") == "neutral"
        ]
        negative_findings = [
            f for f in findings if f.get("score_impact", {}).get("type") == "penalty"
        ]

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
            "score_changes": score_changes,
        }
