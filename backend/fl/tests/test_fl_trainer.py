import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, Mock, MagicMock

import pandas as pd
import torch

from fl.src.fl_trainer import (
    _train_local,
    add_differential_privacy_noise,
    aggregate_median,
    aggregate_secure_average,
    aggregate_weighted,
    calculate_model_similarity,
    create_federated_experiment_config,
    evaluate_federated_model,
    generate_fl_datasets,
    save_federated_results,
)
from ml.src.ml_trainer import SecurityNN


class TestGenerateFlDatasets(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tempdir)

    @patch("fl.src.fl_trainer.SecurityExpertSystem")
    @patch("fl.src.fl_trainer.generate_dataset")
    @patch("fl.src.fl_trainer.split_dataset")
    @patch("fl.src.fl_trainer.save_to_csv")
    def test_default_behavior(self, mock_save, mock_split, mock_gen, mock_expert):
        mock_expert.return_value = Mock()
        mock_gen.return_value = [1]
        mock_split.return_value = ([1], [1])

        datasets = generate_fl_datasets(output_dir=self.tempdir)

        # Four clients created by default
        self.assertEqual(len(datasets), 4)
        # Dataset generation and saving called for each client
        self.assertEqual(mock_gen.call_count, 4)
        self.assertEqual(
            mock_save.call_count, 8
        )  # Ensure each returned dict has train and test paths
        for ds in datasets:
            self.assertIn("train", ds)
            self.assertIn("test", ds)

    @patch("fl.src.fl_trainer.SecurityExpertSystem")
    @patch("fl.src.fl_trainer.generate_dataset")
    @patch("fl.src.fl_trainer.split_dataset")
    @patch("fl.src.fl_trainer.save_to_csv")
    def test_bias_increment(self, _, mock_split, mock_gen, mock_expert):
        mock_expert.return_value = Mock()
        mock_gen.return_value = [1]
        mock_split.return_value = ([1], [1])

        num_clients = 3
        base = 0.2
        step = 0.1
        datasets = generate_fl_datasets(
            num_clients=num_clients,
            samples_per_client=100,
            excellent_base=base,
            excellent_step=step,
            output_dir=self.tempdir,
        )

        # Returned list length matches number of clients
        self.assertEqual(len(datasets), num_clients)

        # Validate bias applied per client call
        calls = mock_gen.call_args_list
        for idx, call in enumerate(calls):
            # bias value is the third positional argument
            _, _, bias = call[0]
            expected_bias = base + idx * step
            self.assertAlmostEqual(bias, expected_bias)


class TestLocalTraining(unittest.TestCase):
    def setUp(self):
        self.model = SecurityNN(3, 5, 1)
        self.device = torch.device("cpu")

    def make_loader(self, with_grade=False):
        x = torch.randn(4, 3)
        y_score = torch.randn(4, 1)
        if with_grade:
            y_grade = torch.randint(0, 5, (4,))
            dataset = [(x, y_score, y_grade)]
        else:
            dataset = [(x, y_score)]
        loader = MagicMock()
        loader.__iter__.return_value = iter(dataset)
        return loader

    def test_score_only_training(self):
        loader = self.make_loader(False)
        params_before = {k: v.clone() for k, v in self.model.named_parameters()}

        _train_local(model=self.model, loader=loader, epochs=1, device=self.device)

        changed = any(
            not torch.equal(params_before[name], param)
            for name, param in self.model.named_parameters()
        )
        self.assertTrue(changed)

    def test_score_and_grade_training(self):
        loader = self.make_loader(True)
        params_before = {k: v.clone() for k, v in self.model.named_parameters()}

        _train_local(model=self.model, loader=loader, epochs=1, device=self.device)

        changed = any(
            not torch.equal(params_before[name], param)
            for name, param in self.model.named_parameters()
        )
        self.assertTrue(changed)


class TestAggregationMethods(unittest.TestCase):
    def setUp(self):
        self.s1 = {"w": torch.tensor([1.0, 2.0])}
        self.s2 = {"w": torch.tensor([3.0, 4.0])}

    def test_weighted_aggregation(self):
        result = aggregate_weighted([self.s1, self.s2], weights=[1, 1])
        expected = torch.tensor([2.0, 3.0])
        self.assertTrue(torch.allclose(result["w"], expected))

    def test_median_aggregation(self):
        result = aggregate_median([self.s1, self.s2, self.s1])
        expected = torch.tensor([1.0, 2.0])
        self.assertTrue(torch.allclose(result["w"], expected))


class TestSimilarityAndPrivacy(unittest.TestCase):
    def test_model_similarity_perfect(self):
        state = {"a": torch.tensor([1.0, 0.0])}
        similarity = calculate_model_similarity(state, state)
        self.assertAlmostEqual(similarity, 1.0)

    def test_noise_addition_zero_scale(self):
        state = {"a": torch.tensor([0.5, 0.5])}
        noisy = add_differential_privacy_noise(state, noise_scale=0.0)
        self.assertTrue(torch.allclose(noisy["a"], state["a"]))


class TestSecureAggregation(unittest.TestCase):
    def test_secure_average_without_noise(self):
        states = [{"a": torch.tensor([1.0])}, {"a": torch.tensor([3.0])}]
        result = aggregate_secure_average(states, add_noise=False)
        self.assertTrue(torch.allclose(result["a"], torch.tensor([2.0])))


class TestEvaluateFederatedModel(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        df = pd.DataFrame({"f1": [1], "target_score": [1]})
        for i in (1, 2):
            df.to_csv(Path(self.tmpdir) / f"test{i}.csv", index=False)

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    @patch("fl.src.fl_trainer.evaluate_security_model")
    def test_evaluate_federated_model_stats(self, mock_eval):
        mock_eval.side_effect = [
            {"mse": 1, "mae": 2, "r2_score": 0.5},
            {"mse": 3, "mae": 4, "r2_score": 0.7},
        ]

        results = evaluate_federated_model(
            global_model=None,
            client_test_paths=[
                Path(self.tmpdir) / "test1.csv",
                Path(self.tmpdir) / "test2.csv",
            ],
            encoders=None,
            scaler=None,
            grade_encoder=None,
            base_dataset=None,
        )

        self.assertEqual(results["avg_mse"], 2.0)
        self.assertAlmostEqual(results["std_mse"], 1.0)


class TestSaveAndConfig(unittest.TestCase):
    def test_save_federated_results_and_config(self):
        tmpdir = tempfile.mkdtemp()
        history = {"m": [1, 2]}
        config = {"a": 1}

        save_federated_results(history, Path(tmpdir), config)

        self.assertTrue((Path(tmpdir) / "fl_training_history.csv").exists())
        self.assertTrue((Path(tmpdir) / "fl_config.json").exists())

        shutil.rmtree(tmpdir)

    def test_create_experiment_config_defaults(self):
        cfg = create_federated_experiment_config()
        self.assertEqual(cfg["num_clients"], 4)
        self.assertEqual(cfg["aggregation"], "weighted")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
