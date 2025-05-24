"""
Unit tests for system security scanner functionality.
Validates Windows security settings retrieval using mocked system commands.
Tests focus on firewall status and password policy parsing.
"""

from unittest.mock import patch
import unittest
import platform
import types
import psutil
from scanner import (
    get_firewall_status,
    get_password_policy,
    get_patch_status,
    get_open_ports,
    get_running_services,
    get_antivirus_status,
)


@unittest.skipIf(
    platform.system() != "Windows",
    "Skipping Windows-specific tests on non-Windows platforms",
)
class TestScanner(unittest.TestCase):
    @patch("scanner.subprocess.check_output")
    def test_firewall_profiles_dict(self, mock_check_output):
        """Verifies firewall status parsing returns correctly structured profile dictionary.
        Tests parsing of multi-profile netsh output format."""
        # Mock netsh output with all three firewall profiles
        mock_output = (
            "Domain Profile Settings:\n"
            "State                 ON\n"
            "Private Profile Settings:\n"
            "State                 OFF\n"
            "Public Profile Settings:\n"
            "State                 OFF\n"
        )
        mock_check_output.return_value = mock_output
        profiles = get_firewall_status().get("profiles")
        self.assertIsInstance(profiles, dict)

    @patch("scanner.subprocess.check_output")
    def test_domain_in_profiles(self, mock_check_output):
        """Verifies domain profile is correctly extracted from firewall settings.
        Tests minimal netsh output containing only domain profile."""
        # Mock netsh output with single profile
        mock_output = "Domain Profile Settings:\n" "State                 OFF\n"
        mock_check_output.return_value = mock_output
        profiles = get_firewall_status().get("profiles")
        self.assertIn("domain", profiles)

    @patch("scanner.subprocess.check_output")
    def test_min_password_length(self, mock_check_output):
        """Validates password length policy parsing and minimum value enforcement.
        Tests fallback behavior when policy value is missing or invalid."""
        # Mock net accounts output with missing password length
        mock_output = "Some Other Setting      0\n"
        mock_check_output.return_value = mock_output
        policy = get_password_policy().get("policy")
        self.assertGreaterEqual(policy.get("min_password_length", 0), 1)

    @patch("scanner.subprocess.check_output")
    def test_password_policy_parsing(self, mock_check_output):
        """Parse valid net accounts output for min length and max age."""
        mock_output = (
            "Minimum password length          7\n"
            "Maximum password age             42\n"
        )
        mock_check_output.return_value = mock_output
        policy = get_password_policy()["policy"]
        self.assertEqual(policy["min_password_length"], 7)
        self.assertEqual(policy["max_password_age"], 42)

    @patch("scanner.subprocess.check_output")
    def test_password_policy_defaults_when_missing(self, mock_check_output):
        """Missing settings yield defaults: min=1 and max age=0."""
        mock_output = "Some irrelevant setting         0\n"
        mock_check_output.return_value = mock_output
        policy = get_password_policy()["policy"]
        self.assertEqual(policy["min_password_length"], 1)
        self.assertEqual(policy["max_password_age"], 0)

    @patch("scanner.c.Win32_QuickFixEngineering")
    def test_patch_status_out_of_date_no_hotfixes(self, mock_wql):
        """No hotfixes → status 'out-of-date' and empty list."""
        mock_wql.return_value = []
        result = get_patch_status()
        self.assertEqual(result["status"], "out-of-date")
        self.assertEqual(result["hotfixes"], [])

    @patch("scanner.c.Win32_QuickFixEngineering")
    def test_patch_status_up_to_date_with_hotfixes(self, mock_wql):
        """Hotfixes present → status 'up-to-date' and list returned."""
        fake = types.SimpleNamespace(HotFixID="KB123")
        mock_wql.return_value = [fake]
        result = get_patch_status()
        self.assertEqual(result["status"], "up-to-date")
        self.assertEqual(result["hotfixes"], ["KB123"])

    @patch("scanner.psutil.net_connections")
    def test_open_ports_filters_listening(self, mock_net):
        """Only LISTENING connections are returned."""
        addr1 = types.SimpleNamespace(port=80)
        addr2 = types.SimpleNamespace(port=22)
        conn1 = types.SimpleNamespace(status=psutil.CONN_LISTEN, laddr=addr1)
        conn2 = types.SimpleNamespace(status="ESTABLISHED", laddr=addr2)
        mock_net.return_value = [conn1, conn2]
        ports = get_open_ports()["ports"]
        self.assertIn(80, ports)
        self.assertNotIn(22, ports)

    @patch("scanner.c.Win32_Service")
    def test_running_services_returns_list(self, mock_services):
        """Services list transformed into dict entries with name & state."""
        svc1 = types.SimpleNamespace(Name="SvcA", State="Running")
        svc2 = types.SimpleNamespace(Name="SvcB", State="Stopped")
        mock_services.return_value = [svc1, svc2]
        out = get_running_services()["services"]
        names = [s["name"] for s in out]
        states = [s["state"] for s in out]
        self.assertCountEqual(names, ["SvcA", "SvcB"])
        self.assertCountEqual(states, ["Running", "Stopped"])

    @patch("scanner.wmi.WMI")
    def test_antivirus_status_empty_list(self, mock_wmi):
        """No antivirus products → empty list."""
        sec = types.SimpleNamespace(AntiVirusProduct=lambda: [])
        mock_wmi.return_value = sec
        result = get_antivirus_status()
        self.assertEqual(result["products"], [])

    @patch("scanner.wmi.WMI")
    def test_antivirus_status_with_products(self, mock_wmi):
        """Detect multiple AV products with name and state."""
        av1 = types.SimpleNamespace(displayName="AV1", productState=123)
        av2 = types.SimpleNamespace(displayName="AV2", productState=None)
        sec = types.SimpleNamespace(AntiVirusProduct=lambda: [av1, av2])
        mock_wmi.return_value = sec
        result = get_antivirus_status()["products"]
        self.assertEqual(len(result), 2)
        self.assertIn({"name": "AV1", "state": 123}, result)
        self.assertIn({"name": "AV2", "state": None}, result)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
