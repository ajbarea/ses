import unittest
from pathlib import Path
import sys

# Adjust path to import from backend.src
# Assuming this test file is in backend/tests/ and the main code is in backend/src/
# This adds the 'backend' directory to sys.path, allowing 'from src import ...'
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.data_generator import (
    generate_patch_metric,
    generate_ports_metric,
    generate_services_metric,
    generate_firewall_metric,
    generate_antivirus_metric,
    generate_password_policy_metric,
    generate_single_metric_set,
    flatten_metrics
)

class TestMetricGenerators(unittest.TestCase):

    def test_generate_patch_metric(self):
        metric = generate_patch_metric()
        self.assertIn("status", metric)
        self.assertIn("hotfixes", metric)
        self.assertIsInstance(metric["status"], str)
        self.assertIn(metric["status"], ["up-to-date", "out-of-date"])
        self.assertIsInstance(metric["hotfixes"], list)
        if metric["hotfixes"]: # Hotfixes can be an empty list
            self.assertTrue(all(isinstance(h, str) for h in metric["hotfixes"]))

    def test_generate_ports_metric(self):
        metric = generate_ports_metric()
        self.assertIn("ports", metric)
        self.assertIsInstance(metric["ports"], list)
        if metric["ports"]: # Ports can be an empty list
            self.assertTrue(all(isinstance(p, int) for p in metric["ports"]))
            self.assertTrue(all(0 < p < 65536 for p in metric["ports"]))

    def test_generate_services_metric(self):
        metric = generate_services_metric()
        self.assertIn("services", metric)
        self.assertIsInstance(metric["services"], list)
        if metric["services"]: # Services can be an empty list
            self.assertTrue(all(isinstance(s, dict) for s in metric["services"]))
            for service in metric["services"]:
                self.assertIn("name", service)
                self.assertIn("state", service)
                self.assertIsInstance(service["name"], str)
                self.assertIn(service["state"], ["Running", "Stopped"])

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
        if metric["products"]: # Products can be an empty list
            self.assertTrue(all(isinstance(p, dict) for p in metric["products"]))
            for product in metric["products"]:
                self.assertIn("name", product)
                self.assertIsInstance(product["name"], str)
                self.assertIn("state", product)
                # State can be int, str ("UNKNOWN"), or None
                self.assertTrue(isinstance(product["state"], (int, str, type(None))))
                if isinstance(product["state"], str):
                    self.assertEqual(product["state"], "UNKNOWN")


    def test_generate_password_policy_metric(self):
        metric = generate_password_policy_metric()
        self.assertIn("policy", metric)
        self.assertIsInstance(metric["policy"], dict)
        self.assertIn("min_password_length", metric["policy"])
        self.assertIn("max_password_age", metric["policy"])
        self.assertIsInstance(metric["policy"]["min_password_length"], int)
        self.assertIsInstance(metric["policy"]["max_password_age"], int)
        self.assertIn(metric["policy"]["min_password_length"], [0, 6, 8, 10, 12, 14])
        self.assertIn(metric["policy"]["max_password_age"], [0, 30, 60, 90, 180, 365])

class TestFlattenMetrics(unittest.TestCase):

    def test_flatten_metrics_basic(self):
        sample_metrics = {
            "patch_metric": {"status": "up-to-date", "hotfixes": ["KB1", "KB2"]},
            "ports_metric": {"ports": [80, 443, 8080]},
            "services_metric": {"services": [{"name": "s1", "state": "Running"}]},
            "firewall_metric": {"profiles": {"domain": "ON", "private": "OFF", "public": "ON"}},
            "antivirus_metric": {"products": [{"name": "AV1", "state": 397312}]},
            "password_policy_metric": {"policy": {"min_password_length": 8, "max_password_age": 90}}
        }
        flat = flatten_metrics(sample_metrics)

        expected_keys = [
            "patch_status", "patch_hotfixes_count", "ports_count", "services_count",
            "firewall_domain_status", "firewall_private_status", "firewall_public_status",
            "antivirus_products_count", "password_policy_min_length", "password_policy_max_age"
        ]
        for key in expected_keys:
            self.assertIn(key, flat)

        self.assertEqual(flat["patch_status"], "up-to-date")
        self.assertEqual(flat["patch_hotfixes_count"], 2)
        self.assertEqual(flat["ports_count"], 3)
        self.assertEqual(flat["services_count"], 1)
        self.assertEqual(flat["firewall_domain_status"], "ON")
        self.assertEqual(flat["firewall_private_status"], "OFF")
        self.assertEqual(flat["firewall_public_status"], "ON")
        self.assertEqual(flat["antivirus_products_count"], 1)
        self.assertEqual(flat["password_policy_min_length"], 8)
        self.assertEqual(flat["password_policy_max_age"], 90)

    def test_flatten_metrics_empty_or_missing(self):
        sample_metrics = {
            "patch_metric": {"status": "out-of-date", "hotfixes": []},
            # ports_metric is missing
            "services_metric": {"services": []},
            "firewall_metric": {"profiles": {"domain": "UNKNOWN", "private": "UNKNOWN", "public": "UNKNOWN"}},
            "antivirus_metric": {"products": []},
            "password_policy_metric": {"policy": {}} # min_length and max_age missing
        }
        flat = flatten_metrics(sample_metrics)

        self.assertEqual(flat["patch_status"], "out-of-date")
        self.assertEqual(flat["patch_hotfixes_count"], 0)
        self.assertEqual(flat["ports_count"], 0) # Missing ports_metric
        self.assertEqual(flat["services_count"], 0)
        self.assertEqual(flat["firewall_domain_status"], "UNKNOWN")
        self.assertEqual(flat["antivirus_products_count"], 0)
        self.assertEqual(flat["password_policy_min_length"], 0) # Default for missing
        self.assertEqual(flat["password_policy_max_age"], 0)   # Default for missing

    def test_flatten_metrics_all_missing(self):
        sample_metrics = {} # All top-level metric keys are missing
        flat = flatten_metrics(sample_metrics)

        self.assertEqual(flat["patch_status"], "unknown")
        self.assertEqual(flat["patch_hotfixes_count"], 0)
        self.assertEqual(flat["ports_count"], 0)
        self.assertEqual(flat["services_count"], 0)
        self.assertEqual(flat["firewall_domain_status"], "UNKNOWN")
        self.assertEqual(flat["firewall_private_status"], "UNKNOWN")
        self.assertEqual(flat["firewall_public_status"], "UNKNOWN")
        self.assertEqual(flat["antivirus_products_count"], 0)
        self.assertEqual(flat["password_policy_min_length"], 0)
        self.assertEqual(flat["password_policy_max_age"], 0)

    def test_generate_single_metric_set_structure(self):
        """Tests if generate_single_metric_set returns a dict with all expected metric keys."""
        metric_set = generate_single_metric_set()
        expected_top_keys = [
            "patch_metric", "ports_metric", "services_metric",
            "firewall_metric", "antivirus_metric", "password_policy_metric"
        ]
        for key in expected_top_keys:
            self.assertIn(key, metric_set)
            self.assertIsInstance(metric_set[key], dict)


if __name__ == '__main__':
    unittest.main()
