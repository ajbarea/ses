import unittest
from scanner import get_firewall_status, get_password_policy


class TestScanner(unittest.TestCase):
    def test_firewall_profiles_dict(self):
        profiles = get_firewall_status().get("profiles")
        self.assertIsInstance(profiles, dict)

    def test_domain_in_profiles(self):
        profiles = get_firewall_status()["profiles"]
        self.assertIn("domain", profiles)

    def test_min_password_length(self):
        min_length = get_password_policy()["policy"].get("min_password_length")
        self.assertGreaterEqual(min_length, 1)


if __name__ == "__main__":
    unittest.main()
