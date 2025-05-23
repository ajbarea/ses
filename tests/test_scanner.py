"""
Unit tests for system security scanner functionality.
Validates Windows security settings retrieval using mocked system commands.
Tests focus on firewall status and password policy parsing.
"""

from unittest.mock import patch
import unittest
from scanner import get_firewall_status, get_password_policy


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


if __name__ == "__main__":
    unittest.main()
