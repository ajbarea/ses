"""Unit tests for data_generator.py module's security metrics generation and processing."""

import unittest
import tempfile
import csv
from pathlib import Path
from unittest.mock import patch, MagicMock
import io

from src.data_generator import (
    generate_patch_metric,
    generate_ports_metric,
    generate_services_metric,
    generate_firewall_metric,
    generate_antivirus_metric,
    generate_password_policy_metric,
    generate_single_metric_set,
    flatten_metrics,
    generate_dataset,
    save_to_csv,
    split_dataset,
)


class TestMetricGenerators(unittest.TestCase):
    """Tests for individual security metric generator functions."""

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
                self.assertIsInstance(product["state"], (int, str, type(None)))
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
        """Verifies that all required metric categories are present in generated set."""
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
    """Tests for metric flattening functionality that transforms nested metrics into ML-ready format."""

    def test_flatten_metrics_basic(self):
        """Tests flattening of a complete, well-formed metrics dictionary."""
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
        """Tests handling of partially populated or empty metric categories."""
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
        """Tests handling of completely empty metrics dictionary."""
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
    """Mock security expert system for testing dataset generation.

    Implements a simplified scoring system:
    - Base score: 100 points
    - Deductions:
        - Out-of-date patches: -30
        - Disabled firewall: -25
        - Disabled antivirus: -20

    Grade thresholds:
        - Excellent: >= 90
        - Good: >= 80
        - Fair: >= 60
        - Poor: >= 40
        - Critical Risk: < 40
    """

    def evaluate(self, metrics):
        """Simulates security metric evaluation with simplified scoring logic.

        Args:
            metrics: Dictionary of security metrics

        Returns:
            Dict containing score (0-100), grade, and list of findings
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


class TestGenerateDataset(unittest.TestCase):
    """Tests for dataset generation using the expert system."""

    @patch("sys.stdout", new_callable=io.StringIO)
    def test_generate_dataset_size(self, mock_stdout):
        """Tests dataset size and progress reporting."""
        num_samples = 100
        expert_system = MockExpertSystem()
        dataset = generate_dataset(expert_system, num_samples)

        # Check if we got the right number of samples
        self.assertEqual(len(dataset), num_samples)

        # Check if each sample has the expected structure
        for sample in dataset:
            self.assertIn("target_score", sample)
            self.assertIn("target_grade", sample)
            # Check for some of the flattened metrics
            self.assertIn("patch_status", sample)
            self.assertIn("firewall_domain", sample)
            self.assertIn("antivirus_enabled", sample)

        # Check for progress print
        self.assertIn(f"Progress: {num_samples}/{num_samples}", mock_stdout.getvalue())

    def test_generate_dataset_with_zero_samples(self):
        """Test if generate_dataset handles zero samples correctly."""
        expert_system = MockExpertSystem()
        dataset = generate_dataset(expert_system, 0)
        self.assertEqual(len(dataset), 0)

    def test_generate_dataset_expert_system_error(self):
        """Tests error handling when expert system evaluation fails."""
        num_samples = 1
        mock_expert_system = MagicMock()
        # Simulate evaluate returning None or an incomplete dict
        mock_expert_system.evaluate.return_value = None

        dataset = generate_dataset(mock_expert_system, num_samples)
        self.assertEqual(len(dataset), num_samples)
        self.assertIsNone(dataset[0]["target_score"])
        self.assertEqual(dataset[0]["target_grade"], "Error")

        mock_expert_system.evaluate.return_value = {
            "some_other_key": "value"
        }  # Incomplete dict
        dataset = generate_dataset(mock_expert_system, num_samples)
        self.assertEqual(len(dataset), num_samples)
        self.assertIsNone(dataset[0]["target_score"])
        self.assertEqual(dataset[0]["target_grade"], "Error")


class TestSaveToCSV(unittest.TestCase):
    """Tests for CSV file output functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_data = [
            {"col1": "value1", "col2": 10, "col3": True},
            {"col1": "value2", "col2": 20, "col3": False},
        ]

    def tearDown(self):
        """Tear down test fixtures."""
        self.temp_dir.cleanup()

    def test_save_to_csv_normal(self):
        """Tests successful CSV file writing with valid data."""
        filepath = Path(self.temp_dir.name) / "test_output.csv"
        save_to_csv(self.test_data, filepath)

        # Verify the file exists
        self.assertTrue(filepath.exists())

        # Verify the file contents
        with open(filepath, "r", newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[0]["col1"], "value1")
            self.assertEqual(rows[0]["col2"], "10")
            self.assertEqual(rows[0]["col3"], "True")
            self.assertEqual(rows[1]["col1"], "value2")

    def test_save_to_csv_empty(self):
        """Tests CSV handling with empty dataset.

        Note: Implementation may either create an empty file or not create one at all.
        Both behaviors are acceptable."""
        filepath = Path(self.temp_dir.name) / "empty_output.csv"
        save_to_csv([], filepath)

        # If file exists, it should be empty
        if filepath.exists():
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read().strip()
            self.assertEqual(content, "")

    @patch("sys.stdout", new_callable=io.StringIO)
    @patch("builtins.open", side_effect=IOError("Simulated I/O Error"))
    def test_save_to_csv_io_error(self, mock_open, mock_stdout):
        """Tests error handling during CSV file writing."""
        filepath = Path(self.temp_dir.name) / "error_output.csv"
        save_to_csv(self.test_data, filepath)

        # Verify the error message was printed to stdout
        self.assertIn("Error saving CSV: Simulated I/O Error", mock_stdout.getvalue())
        # Verify that open was called
        mock_open.assert_called_once_with(filepath, "w", newline="", encoding="utf-8")

    def test_save_to_csv_empty_file_preexisting(self):
        """Empty dataset should truncate an existing file to empty."""
        filepath = Path(self.temp_dir.name) / "prepopulated.csv"
        # pre-create with content
        filepath.write_text("placeholder")
        save_to_csv([], filepath)
        self.assertTrue(filepath.exists())
        # now must be empty
        self.assertEqual(filepath.read_text().strip(), "")


class TestSplitDataset(unittest.TestCase):
    """Tests for dataset splitting into training and testing sets."""

    def test_split_dataset_normal(self):
        """Tests standard 80/20 train/test split."""
        dataset = [{"id": i} for i in range(100)]
        train_ratio = 0.8

        train_data, test_data = split_dataset(dataset, train_ratio)

        # Check if the sizes are correct
        self.assertEqual(len(train_data), 80)
        self.assertEqual(len(test_data), 20)

        # Check if the data is split correctly
        self.assertEqual(train_data[0]["id"], 0)
        self.assertEqual(test_data[0]["id"], 80)

    def test_split_dataset_edge_ratios(self):
        """Tests extreme split ratios (90/10 and 10/90)."""
        dataset = [{"id": i} for i in range(10)]

        # Nearly all training data
        train_data, test_data = split_dataset(dataset, 0.9)
        self.assertEqual(len(train_data), 9)
        self.assertEqual(len(test_data), 1)

        # Nearly all testing data
        train_data, test_data = split_dataset(dataset, 0.1)
        self.assertEqual(len(train_data), 1)
        self.assertEqual(len(test_data), 9)

    def test_split_dataset_empty(self):
        """Test splitting an empty dataset."""
        dataset = []
        train_data, test_data = split_dataset(dataset, 0.8)
        self.assertEqual(len(train_data), 0)
        self.assertEqual(len(test_data), 0)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
