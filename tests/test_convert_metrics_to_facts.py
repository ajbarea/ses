import unittest
from unittest.mock import MagicMock
from clips_evaluator import SecurityExpertSystem


class TestConvertMetricsToFacts(unittest.TestCase):
    def setUp(self):
        self.expert = SecurityExpertSystem(rules_dir=None)
        # Mock the CLIPS environment
        self.expert.env = MagicMock()
        self.expert.env.reset = MagicMock()
        self.expert.env.assert_string = MagicMock()

    def test_ports_to_open_port_facts(self):
        data = {"ports": {"ports": [22, 80]}}
        self.expert.convert_metrics_to_facts(data)
        self.expert.env.assert_string.assert_any_call("(open-port (number 22))")
        self.expert.env.assert_string.assert_any_call("(open-port (number 80))")

    def test_services_to_service_facts(self):
        services = [
            {"name": "SvcA", "state": "Running"},
            {"name": "SvcB", "state": "Stopped"},
        ]
        data = {"services": {"services": services}}
        self.expert.convert_metrics_to_facts(data)
        self.expert.env.assert_string.assert_any_call(
            '(service (name "SvcA") (state "Running"))'
        )
        self.expert.env.assert_string.assert_any_call(
            '(service (name "SvcB") (state "Stopped"))'
        )

    def test_antivirus_to_antivirus_product_facts(self):
        products = [{"name": "AVX", "state": 5}, {"name": "AVY", "state": None}]
        data = {"antivirus": {"products": products}}
        self.expert.convert_metrics_to_facts(data)
        self.expert.env.assert_string.assert_any_call(
            '(antivirus-product (name "AVX") (state 5))'
        )
        self.expert.env.assert_string.assert_any_call(
            '(antivirus-product (name "AVY") (state UNKNOWN))'
        )

    def test_password_policy_to_password_policy_fact(self):
        policy = {"min_password_length": 5, "max_password_age": 15}
        data = {"password_policy": {"policy": policy}}
        self.expert.convert_metrics_to_facts(data)
        self.expert.env.assert_string.assert_any_call(
            "(password-policy (min-password-length 5) (max-password-age 15))"
        )


if __name__ == "__main__":
    unittest.main()
