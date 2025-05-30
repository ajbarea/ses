"""
Unit tests for system security scanner functionality using mocks.
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
        """Ensure firewall status parsing returns correct profile dictionary."""
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
        """Ensure domain profile is correctly extracted."""
        # Mock netsh output with single profile
        mock_output = "Domain Profile Settings:\nState                 OFF\n"
        mock_check_output.return_value = mock_output
        profiles = get_firewall_status().get("profiles")
        self.assertIn("domain", profiles)

    @patch("src.scanner.subprocess.check_output")
    def test_min_password_length(self, mock_check_output):
        """Verify password minimum length enforcement."""
        # Mock net accounts output with missing password length
        mock_output = "Some Other Setting      0\n"
        mock_check_output.return_value = mock_output
        policy = get_password_policy().get("policy")
        self.assertGreaterEqual(policy.get("min_password_length", 0), 1)

    @patch("src.scanner.subprocess.check_output")
    def test_password_policy_parsing(self, mock_check_output):
        """Verify min length and max age parsing from net accounts."""
        mock_output = (
            "Minimum password length          7\n"
            "Maximum password age             42\n"
        )
        mock_check_output.return_value = mock_output
        policy = get_password_policy()["policy"]
        self.assertEqual(policy["min_password_length"], 7)
        self.assertEqual(policy["max_password_age"], 42)

    @patch("src.scanner.subprocess.check_output")
    def test_password_policy_defaults_when_missing(self, mock_check_output):
        """Check default policy values when settings are missing."""
        mock_output = "Some irrelevant setting         0\n"
        mock_check_output.return_value = mock_output
        policy = get_password_policy()["policy"]
        self.assertEqual(policy["min_password_length"], 1)
        self.assertEqual(policy["max_password_age"], 0)

    @patch("src.scanner.c.Win32_QuickFixEngineering")
    def test_patch_status_out_of_date_no_hotfixes(self, mock_wql):
        """Check out-of-date status with no hotfixes."""
        mock_wql.return_value = []
        result = get_patch_status()
        self.assertEqual(result["status"], "out-of-date")
        self.assertEqual(result["hotfixes"], [])

    @patch("src.scanner.c.Win32_QuickFixEngineering")
    def test_patch_status_up_to_date_with_hotfixes(self, mock_wql):
        """Check up-to-date status with hotfixes present."""
        fake = types.SimpleNamespace(HotFixID="KB123")
        mock_wql.return_value = [fake]
        result = get_patch_status()
        self.assertEqual(result["status"], "up-to-date")
        self.assertEqual(result["hotfixes"], ["KB123"])

    @patch("src.scanner.psutil.net_connections")
    def test_open_ports_filters_listening(self, mock_net):
        """Confirm only LISTENING ports are returned."""
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
        """psutil path should only return services whose status() == "running"."""
        svc1 = types.SimpleNamespace(name=lambda: "SvcA", status=lambda: "running")
        svc2 = types.SimpleNamespace(name=lambda: "SvcB", status=lambda: "stopped")
        mock_iter.return_value = [svc1, svc2]

        out = get_running_services()["services"]
        names = [s["name"] for s in out]
        states = [s["state"] for s in out]

        # only SvcA/running survives the filter
        self.assertCountEqual(names, ["SvcA"])
        self.assertCountEqual(states, ["running"])

    @patch("src.scanner.psutil.win_service_iter", side_effect=Exception)
    @patch("src.scanner.c.Win32_Service")
    def test_running_services_fallback_to_wmi(self, mock_services, mock_iter):
        """When psutil fails, fallback to WMI and still only return running services."""
        svc1 = types.SimpleNamespace(Name="SvcA", State="Running")
        svc2 = types.SimpleNamespace(Name="SvcB", State="Stopped")
        mock_services.return_value = [svc1, svc2]

        out = get_running_services()["services"]
        names = [s["name"] for s in out]
        states = [s["state"] for s in out]

        # only the Running service should be returned
        self.assertCountEqual(names, ["SvcA"])
        self.assertCountEqual(states, ["Running"])

    @patch("src.scanner.wmi.WMI")
    def test_antivirus_status_empty_list(self, mock_wmi):
        """Ensure empty list when no antivirus found."""
        sec = types.SimpleNamespace(AntiVirusProduct=lambda: [])
        mock_wmi.return_value = sec
        result = get_antivirus_status()
        self.assertEqual(result["products"], [])

    @patch("src.scanner.wmi.WMI")
    def test_antivirus_status_with_products(self, mock_wmi):
        """Check multiple AV products with name and state."""
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
