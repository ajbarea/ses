import unittest
import torch

from fl.src.fl_trainer import (
    aggregate_average,
    aggregate_median,
    aggregate_weighted,
)


class TestFederatedAggregations(unittest.TestCase):
    def setUp(self):
        self.state1 = {"w": torch.tensor([1.0, 2.0])}
        self.state2 = {"w": torch.tensor([3.0, 4.0])}

    def test_average(self):
        agg = aggregate_average([self.state1, self.state2])
        self.assertTrue(torch.allclose(agg["w"], torch.tensor([2.0, 3.0])))

    def test_weighted(self):
        agg = aggregate_weighted([self.state1, self.state2], weights=[2.0, 1.0])
        expected = (self.state1["w"] * 2 + self.state2["w"]) / 3
        self.assertTrue(torch.allclose(agg["w"], expected))

    def test_median(self):
        agg = aggregate_median([self.state1, self.state2])
        self.assertTrue(torch.allclose(agg["w"], torch.tensor([2.0, 3.0])))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
