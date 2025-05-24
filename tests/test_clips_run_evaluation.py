import unittest
from unittest.mock import MagicMock
from clips_evaluator import SecurityExpertSystem


class TestRunEvaluation(unittest.TestCase):
    def setUp(self):
        self.expert = SecurityExpertSystem(rules_dir=None)
        self.mock_env = MagicMock()
        self.expert.env = self.mock_env
        # default facts to avoid errors
        self.mock_env.facts = MagicMock(return_value=[])

    def test_watch_supported_traces_rules(self):
        # simulate watch supported
        self.mock_env.watch = MagicMock()
        self.mock_env.unwatch = MagicMock()

        # side effect: print activation lines while run() is called
        def run_side_effect():
            print("FIRE 1 ruleA")
            print("FIRE 2 ruleB")
            return 2

        self.mock_env.run = MagicMock(side_effect=run_side_effect)

        fired = self.expert.run_evaluation()
        self.assertEqual(fired, 2)
        self.assertEqual(len(self.expert.rule_activations), 2)
        self.assertEqual(self.expert.rule_activations[0]["rule"], "ruleA")
        self.assertIn("FIRE 1 ruleA", self.expert.rule_activations[0]["activation"])
        self.assertEqual(self.expert.rule_activations[1]["rule"], "ruleB")

    def test_watch_unsupported_fallbacks_to_findings(self):
        # simulate watch unsupported
        self.mock_env.watch = MagicMock(side_effect=AttributeError)
        self.mock_env.run = MagicMock(return_value=5)
        # stub findings for fallback
        findings = [
            {"rule": "r1", "description": "desc1"},
            {"rule": "r2", "description": "desc2"},
        ]
        self.expert.get_findings = MagicMock(return_value=findings)

        fired = self.expert.run_evaluation()
        self.assertEqual(fired, 5)
        # two findings → two activations
        self.assertEqual(len(self.expert.rule_activations), 2)
        self.assertEqual(
            self.expert.rule_activations[0]["activation"], "Rule activated: r1 - desc1"
        )
        self.assertEqual(
            self.expert.rule_activations[1]["activation"], "Rule activated: r2 - desc2"
        )


if __name__ == "__main__":
    unittest.main()
