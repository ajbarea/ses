"""Unit tests for the data generator module that produces security metrics datasets.

Tests the generation of various security metrics including patch status, ports,
services, firewall, antivirus and password policies, as well as the flattening
of these metrics for machine learning purposes.
"""

import unittest

from src.data_generator import (
    generate_patch_metric,
    generate_ports_metric,
    generate_services_metric,
    generate_firewall_metric,
    generate_antivirus_metric,
    generate_password_policy_metric,
    generate_single_metric_set,
    flatten_metrics,
)


class TestMetricGenerators(unittest.TestCase):
    """Test suite for individual metric generator functions."""

    def test_generate_patch_metric(self):
        metric = generate_patch_metric()
        self.assertIn("status", metric)
        self.assertIn("hotfixes", metric)
        self.assertIsInstance(metric["status"], str)
        self.assertIn(metric["status"], ["up-to-date", "out-of-date"])
        self.assertIsInstance(metric["hotfixes"], list)
        if metric["hotfixes"]:
            self.assertTrue(all(isinstance(h, str) for h in metric["hotfixes"]))

    def test_generate_ports_metric(self):
        metric = generate_ports_metric()
        self.assertIn("ports", metric)
        self.assertIsInstance(metric["ports"], list)
        if metric["ports"]:
            self.assertTrue(all(isinstance(p, int) for p in metric["ports"]))
            self.assertTrue(all(0 < p < 65536 for p in metric["ports"]))

    def test_generate_services_metric(self):
        metric = generate_services_metric()
        self.assertIn("services", metric)
        self.assertIsInstance(metric["services"], list)
        if metric["services"]:
            self.assertTrue(all(isinstance(s, dict) for s in metric["services"]))
            for service in metric["services"]:
                self.assertIn("name", service)
                self.assertIn("state", service)
                self.assertIsInstance(service["name"], str)
                self.assertIn(service["state"], ["running", "stopped"])

    def test_generate_firewall_metric(self):
        metric = generate_firewall_metric()
        self.assertIn("profiles", metric)
        self.assertIsInstance(metric["profiles"], dict)
        for profile_type in ["domain", "private", "public"]:
            self.assertIn(profile_type, metric["profiles"])
            self.assertIn(metric["profiles"][profile_type], ["ON", "OFF", "UNKNOWN"])

    def test_generate_antivirus_metric(self):
        metric = generate_antivirus_metric()
        self.assertIn("products", metric)
        self.assertIsInstance(metric["products"], list)
        if metric["products"]:
            self.assertTrue(all(isinstance(p, dict) for p in metric["products"]))
            for product in metric["products"]:
                self.assertIn("name", product)
                self.assertIn("state", product)
                self.assertIsInstance(product["name"], str)
                # State can be int, str ("UNKNOWN"), or None
                self.assertTrue(isinstance(product["state"], (int, str, type(None))))
                if isinstance(product["state"], str):
                    self.assertEqual(product["state"], "UNKNOWN")
                elif isinstance(product["state"], int):
                    self.assertIn(product["state"], [262144, 397312, 397568])

    def test_generate_password_policy_metric(self):
        metric = generate_password_policy_metric()
        self.assertIn("policy", metric)
        self.assertIsInstance(metric["policy"], dict)
        self.assertIn("min_password_length", metric["policy"])
        self.assertIn("max_password_age", metric["policy"])
        self.assertIsInstance(metric["policy"]["min_password_length"], int)
        self.assertIsInstance(metric["policy"]["max_password_age"], int)

    def test_generate_single_metric_set_structure(self):
        """Tests if generate_single_metric_set returns a dict with all expected metric keys."""
        metric_set = generate_single_metric_set()
        expected_keys = [
            "patch",
            "ports",
            "services",
            "firewall",
            "antivirus",
            "password_policy",
        ]
        for key in expected_keys:
            self.assertIn(key, metric_set)
            self.assertIsInstance(metric_set[key], dict)


class TestFlattenMetrics(unittest.TestCase):
    """Test suite for the metrics flattening functionality."""

    def test_flatten_metrics_basic(self):
        sample_metrics = {
            "patch": {"status": "up-to-date", "hotfixes": ["KB1", "KB2"]},
            "ports": {"ports": [80, 443, 8080]},
            "services": {"services": [{"name": "s1", "state": "running"}]},
            "firewall": {
                "profiles": {"domain": "ON", "private": "OFF", "public": "ON"}
            },
            "antivirus": {"products": [{"name": "Windows Defender", "state": 397568}]},
            "password_policy": {
                "policy": {"min_password_length": 8, "max_password_age": 90}
            },
        }
        flat = flatten_metrics(sample_metrics)

        expected_keys = [
            "patch_status",
            "patch_hotfixes_count",
            "ports_count",
            "services_total",
            "services_running",
            "services_stopped",
            "firewall_domain",
            "firewall_private",
            "firewall_public",
            "antivirus_count",
            "antivirus_enabled",
            "password_min_length",
            "password_max_age",
        ]
        for key in expected_keys:
            self.assertIn(key, flat)

        self.assertEqual(flat["patch_status"], "up-to-date")
        self.assertEqual(flat["patch_hotfixes_count"], 2)
        self.assertEqual(flat["ports_count"], 3)
        self.assertEqual(flat["services_total"], 1)
        self.assertEqual(flat["services_running"], 1)
        self.assertEqual(flat["services_stopped"], 0)
        self.assertEqual(flat["firewall_domain"], "ON")
        self.assertEqual(flat["firewall_private"], "OFF")
        self.assertEqual(flat["firewall_public"], "ON")
        self.assertEqual(flat["antivirus_count"], 1)
        self.assertEqual(flat["antivirus_enabled"], 1)
        self.assertEqual(flat["password_min_length"], 8)
        self.assertEqual(flat["password_max_age"], 90)

    def test_flatten_metrics_empty_or_missing(self):
        sample_metrics = {
            "patch": {"status": "out-of-date", "hotfixes": []},
            "services": {"services": []},
            "firewall": {
                "profiles": {
                    "domain": "UNKNOWN",
                    "private": "UNKNOWN",
                    "public": "UNKNOWN",
                }
            },
            "antivirus": {"products": []},
            "password_policy": {"policy": {}},
        }
        flat = flatten_metrics(sample_metrics)

        self.assertEqual(flat["patch_status"], "out-of-date")
        self.assertEqual(flat["patch_hotfixes_count"], 0)
        self.assertEqual(flat["ports_count"], 0)  # Missing ports
        self.assertEqual(flat["services_total"], 0)
        self.assertEqual(flat["services_running"], 0)
        self.assertEqual(flat["services_stopped"], 0)
        self.assertEqual(flat["firewall_domain"], "UNKNOWN")
        self.assertEqual(flat["antivirus_count"], 0)
        self.assertEqual(flat["antivirus_enabled"], 0)
        self.assertEqual(flat["password_min_length"], 0)
        self.assertEqual(flat["password_max_age"], 0)

    def test_flatten_metrics_all_missing(self):
        sample_metrics = {}
        flat = flatten_metrics(sample_metrics)

        self.assertEqual(flat["patch_status"], "unknown")
        self.assertEqual(flat["patch_hotfixes_count"], 0)
        self.assertEqual(flat["ports_count"], 0)
        self.assertEqual(flat["services_total"], 0)
        self.assertEqual(flat["services_running"], 0)
        self.assertEqual(flat["services_stopped"], 0)
        self.assertEqual(flat["firewall_domain"], "UNKNOWN")
        self.assertEqual(flat["firewall_private"], "UNKNOWN")
        self.assertEqual(flat["firewall_public"], "UNKNOWN")
        self.assertEqual(flat["antivirus_count"], 0)
        self.assertEqual(flat["antivirus_enabled"], 0)
        self.assertEqual(flat["password_min_length"], 0)
        self.assertEqual(flat["password_max_age"], 0)


class MockExpertSystem:
    """A mock implementation of the security expert system for testing.

    Simulates the behavior of the real expert system by evaluating security metrics
    and producing scores, grades and findings. Uses a simplified scoring algorithm:
    - Starts with 100 points
    - -30 points for out-of-date patches
    - -25 points for disabled firewall
    - -20 points for disabled antivirus

    Grades are assigned based on score ranges:
    - Excellent: >= 90
    - Good: >= 80
    - Fair: >= 60
    - Poor: >= 40
    - Critical Risk: < 40
    """

    def evaluate(self, metrics):
        """Evaluates security metrics and returns mock assessment results.

        Args:
            metrics: Dict containing security metrics to evaluate

        Returns:
            Dict with keys:
                score: int 0-100 representing overall security score
                grade: str classification of the score
                findings: list of security issues found
        """
        score = 100
        findings = []

        # Check patch status
        if metrics.get("patch", {}).get("status") == "out-of-date":
            score -= 30
            findings.append(
                {
                    "rule": "patch_status_outdated",
                    "level": "critical",
                    "description": "System patches are out-of-date",
                }
            )

        # Check firewall
        firewall_profiles = metrics.get("firewall", {}).get("profiles", {})
        if all(status == "OFF" for status in firewall_profiles.values()):
            score -= 25
            findings.append(
                {
                    "rule": "firewall_all_disabled",
                    "level": "critical",
                    "description": "All firewall profiles are disabled",
                }
            )

        # Check antivirus
        av_products = metrics.get("antivirus", {}).get("products", [])
        if av_products:
            enabled = any(
                isinstance(p.get("state"), int) and p["state"] >= 397312
                for p in av_products
            )
            if not enabled:
                score -= 20
                findings.append(
                    {
                        "rule": "antivirus_disabled",
                        "level": "warning",
                        "description": "Antivirus software is disabled",
                    }
                )

        # Determine grade
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

        return {
            "score": score,
            "grade": grade,
            "findings": findings,
        }


if __name__ == "__main__":
    unittest.main()
