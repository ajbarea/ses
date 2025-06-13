"""
Unit tests for system security scanner functionality using mocks.
Tests the scanner module's ability to extract Windows security information.
"""

from unittest.mock import patch
import unittest
import platform
import types
import psutil

from src.scanner import (
    get_antivirus_status,
    get_firewall_status,
    get_open_ports,
    get_password_policy,
    get_patch_status,
    get_running_services,
)


@unittest.skipIf(
    platform.system() != "Windows",
    "Skipping Windows-specific tests on non-Windows platforms",
)
class TestScanner(unittest.TestCase):
    @patch("src.scanner.subprocess.check_output")
    def test_firewall_profiles_dict(self, mock_check_output):
        """Test that firewall status parsing returns a dictionary with profile information."""
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

    @patch("src.scanner.subprocess.check_output")
    def test_domain_in_profiles(self, mock_check_output):
        """Test that the domain profile is correctly extracted from netsh output."""
        mock_output = "Domain Profile Settings:\nState                 OFF\n"
        mock_check_output.return_value = mock_output
        profiles = get_firewall_status().get("profiles")
        self.assertIn("domain", profiles)

    @patch("src.scanner.subprocess.check_output")
    def test_min_password_length(self, mock_check_output):
        """Test default password length when value is missing from net accounts output."""
        mock_output = "Some Other Setting      0\n"
        mock_check_output.return_value = mock_output
        policy = get_password_policy().get("policy")
        self.assertGreaterEqual(policy.get("min_password_length", 0), 1)

    @patch("src.scanner.subprocess.check_output")
    def test_password_policy_parsing(self, mock_check_output):
        """Test extraction of password policy settings from net accounts output."""
        mock_output = (
            "Minimum password length          7\n"
            "Maximum password age             42\n"
            "Minimum password age             1\n"
            "Password history length          5\n"
            "Lockout threshold                3\n"
            "Password complexity requirements Enabled\n"
        )
        mock_check_output.return_value = mock_output
        policy = get_password_policy()["policy"]
        self.assertEqual(policy["min_password_length"], 7)
        self.assertEqual(policy["max_password_age"], 42)
        self.assertEqual(policy["min_password_age"], 1)
        self.assertEqual(policy["history_size"], 5)
        self.assertEqual(policy["lockout_threshold"], 3)
        self.assertEqual(policy["complexity"], "enabled")

    @patch("src.scanner.subprocess.check_output")
    def test_password_policy_defaults_when_missing(self, mock_check_output):
        """Test that default values are used when password policy settings are missing."""
        mock_output = "Some irrelevant setting         0\n"
        mock_check_output.return_value = mock_output
        policy = get_password_policy()["policy"]
        self.assertEqual(policy["min_password_length"], 1)
        self.assertEqual(policy["max_password_age"], 0)
        self.assertNotIn("complexity", policy)
        self.assertNotIn("lockout_threshold", policy)
        self.assertNotIn("history_size", policy)

    @patch("src.scanner.subprocess.check_output")
    def test_password_policy_handles_disabled_values(self, mock_check_output):
        """Test handling of 'Never' and 'Disabled' values in password policy."""
        mock_output = (
            "Minimum password length          8\n"
            "Maximum password age             Never\n"
            "Password complexity requirements Disabled\n"
        )
        mock_check_output.return_value = mock_output
        policy = get_password_policy()["policy"]
        self.assertEqual(policy["min_password_length"], 8)
        self.assertEqual(policy["max_password_age"], "disabled")
        self.assertEqual(policy["complexity"], "disabled")

    @patch("src.scanner.c.Win32_QuickFixEngineering")
    def test_patch_status_out_of_date_no_hotfixes(self, mock_wql):
        """Test detection of out-of-date patch status when no hotfixes are found."""
        mock_wql.return_value = []
        result = get_patch_status()
        self.assertEqual(result["status"], "out-of-date")
        self.assertEqual(result["hotfixes"], [])

    @patch("src.scanner.c.Win32_QuickFixEngineering")
    def test_patch_status_up_to_date_with_hotfixes(self, mock_wql):
        """Test detection of up-to-date patch status when hotfixes are present."""
        fake = types.SimpleNamespace(HotFixID="KB123")
        mock_wql.return_value = [fake]
        result = get_patch_status()
        self.assertEqual(result["status"], "up-to-date")
        self.assertEqual(result["hotfixes"], ["KB123"])

    @patch("src.scanner.psutil.net_connections")
    def test_open_ports_filters_listening(self, mock_net):
        """Test that only ports in LISTENING state are reported as open."""
        addr1 = types.SimpleNamespace(port=80)
        addr2 = types.SimpleNamespace(port=22)
        conn1 = types.SimpleNamespace(status=psutil.CONN_LISTEN, laddr=addr1)
        conn2 = types.SimpleNamespace(status="ESTABLISHED", laddr=addr2)
        mock_net.return_value = [conn1, conn2]
        ports = get_open_ports()["ports"]
        self.assertIn(80, ports)
        self.assertNotIn(22, ports)

    @patch("src.scanner.psutil.win_service_iter")
    def test_running_services_filters_running(self, mock_iter):
        """Test that only running services are included in the output."""
        svc1 = types.SimpleNamespace(name=lambda: "SvcA", status=lambda: "running")
        svc2 = types.SimpleNamespace(name=lambda: "SvcB", status=lambda: "stopped")
        mock_iter.return_value = [svc1, svc2]

        out = get_running_services()["services"]
        names = [s["name"] for s in out]
        states = [s["state"] for s in out]

        # Only SvcA/running should be included
        self.assertCountEqual(names, ["SvcA"])
        self.assertCountEqual(states, ["running"])

    @patch("src.scanner.psutil.win_service_iter", side_effect=Exception)
    @patch("src.scanner.c.Win32_Service")
    def test_running_services_fallback_to_wmi(self, mock_services, mock_iter):
        """Test fallback to WMI when psutil fails to get services."""
        svc1 = types.SimpleNamespace(Name="SvcA", State="Running")
        svc2 = types.SimpleNamespace(Name="SvcB", State="Stopped")
        mock_services.return_value = [svc1, svc2]

        out = get_running_services()["services"]
        names = [s["name"] for s in out]
        states = [s["state"] for s in out]

        # Only the Running service should be returned
        self.assertCountEqual(names, ["SvcA"])
        self.assertCountEqual(states, ["Running"])

    @patch("src.scanner.wmi.WMI")
    def test_antivirus_status_empty_list(self, mock_wmi):
        """Test handling of no antivirus products detected."""
        sec = types.SimpleNamespace(AntiVirusProduct=lambda: [])
        mock_wmi.return_value = sec
        result = get_antivirus_status()
        self.assertEqual(result["products"], [])

    @patch("src.scanner.wmi.WMI")
    def test_antivirus_status_with_products(self, mock_wmi):
        """Test extraction of multiple antivirus products with their states."""
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
