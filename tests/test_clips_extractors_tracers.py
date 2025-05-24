import unittest
import types
from clips_evaluator import SecurityExpertSystem


# helper fake fact to simulate CLIPS fact objects
class FakeFact(dict):
    def __init__(self, template_name, **kwargs):
        super().__init__(kwargs)
        self.template = types.SimpleNamespace(name=template_name)


class TestExtractorsTracers(unittest.TestCase):
    def setUp(self):
        self.expert = SecurityExpertSystem(rules_dir=None)
        self.expert.rule_activations = []

    def test_get_findings_only_returns_finding_facts(self):
        f1 = FakeFact(
            "finding",
            **{
                "rule-name": "r1",
                "level": "warning",
                "description": "d1",
                "recommendation": "rec1",
                "details": ("a", "b"),
            }
        )
        f2 = FakeFact("other", foo="bar")
        self.expert.env.facts = lambda: [f1, f2]
        findings = self.expert.get_findings()
        self.assertEqual(len(findings), 1)
        self.assertDictEqual(
            findings[0],
            {
                "rule": "r1",
                "level": "warning",
                "description": "d1",
                "recommendation": "rec1",
                "details": ["a", "b"],
            },
        )

    def test_get_score_with_final_score_fact(self):
        f = FakeFact("score", value="85", type="final")
        self.expert.env.facts = lambda: [f]
        score = self.expert.get_score(base_score=50)
        self.assertEqual(score, 85)

    def test_get_score_with_penalty_facts_and_clamping(self):
        f1 = FakeFact("score", value="-150", type="penalty")
        f2 = FakeFact("score", value="30", type="penalty")
        self.expert.env.facts = lambda: [f1, f2]
        # 100 - 150 + 30 = -20 → clamped to 0
        score = self.expert.get_score()
        self.assertEqual(score, 0)

    def test_get_score_falls_back_to_findings(self):
        # no score facts, two findings: critical (-30) + info (-5) = -35 from 100 → 65
        self.expert.env.facts = lambda: []
        self.expert.get_findings = lambda: [{"level": "critical"}, {"level": "info"}]
        score = self.expert.get_score()
        self.assertEqual(score, 65)

    def test_get_rule_trace_returns_activations(self):
        self.expert.rule_activations = [{"rule": "r", "activation": "a"}]
        trace = self.expert.get_rule_trace()
        self.assertIs(trace, self.expert.rule_activations)


if __name__ == "__main__":
    unittest.main()
