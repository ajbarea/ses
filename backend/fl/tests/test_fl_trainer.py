import json
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
    federated_training,
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


class TestDifferentialPrivacyEdgeCases(unittest.TestCase):
    def test_add_differential_privacy_noise_nonzero(self):
        state = {"a": torch.tensor([0.5, 0.5])}
        noisy = add_differential_privacy_noise(state, noise_scale=0.1)
        self.assertEqual(noisy["a"].shape, state["a"].shape)

    def test_add_differential_privacy_noise_clip(self):
        state = {"a": torch.tensor([10.0, 10.0])}
        noisy = add_differential_privacy_noise(state, noise_scale=0.0, clip_norm=1.0)
        self.assertTrue(torch.all(torch.abs(noisy["a"]) <= 1.0))


class TestAggregationEdgeCases(unittest.TestCase):
    def test_aggregate_weighted_empty(self):
        with self.assertRaises(IndexError):
            aggregate_weighted([], [])

    def test_aggregate_median_empty(self):
        with self.assertRaises(IndexError):
            aggregate_median([])

    def test_aggregate_secure_average_with_noise(self):
        states = [{"a": torch.tensor([1.0])}, {"a": torch.tensor([3.0])}]
        result = aggregate_secure_average(states, add_noise=True, noise_scale=0.01)
        self.assertIn("a", result)


class TestModelSimilarityEdgeCases(unittest.TestCase):
    def test_calculate_model_similarity_empty(self):
        sim = calculate_model_similarity({}, {})
        self.assertEqual(sim, 0.0)

    def test_calculate_model_similarity_different_keys(self):
        s1 = {"a": torch.tensor([1.0])}
        s2 = {"b": torch.tensor([1.0])}
        sim = calculate_model_similarity(s1, s2)
        self.assertEqual(sim, 0.0)


class TestEvaluateFederatedModelGradeAcc(unittest.TestCase):
    @patch("fl.src.fl_trainer.evaluate_security_model")
    def test_evaluate_federated_model_with_grade_acc(self, mock_eval):
        mock_eval.side_effect = [
            {"mse": 1, "mae": 2, "r2_score": 0.5, "grade_accuracy": 0.8},
            {"mse": 3, "mae": 4, "r2_score": 0.7, "grade_accuracy": 0.6},
        ]
        results = evaluate_federated_model(
            global_model=None,
            client_test_paths=[Path("a.csv"), Path("b.csv")],
            encoders=None,
            scaler=None,
            grade_encoder=None,
            base_dataset=None,
        )
        self.assertIn("avg_grade_accuracy", results)
        self.assertAlmostEqual(results["avg_grade_accuracy"], 0.7)


class TestSaveFederatedResultsConfig(unittest.TestCase):
    def test_save_federated_results_with_config(self):
        tmpdir = tempfile.mkdtemp()
        history = {"m": [1, 2]}
        config = {"a": 1}
        save_federated_results(history, Path(tmpdir), config)
        config_path = Path(tmpdir) / "fl_config.json"
        self.assertTrue(config_path.exists())
        with open(config_path) as f:
            data = json.load(f)
        self.assertEqual(data["a"], 1)
        shutil.rmtree(tmpdir)


class TestFederatedTrainingAndExperiment(unittest.TestCase):
    def test_federated_training_stub(self):
        # Should not raise, even if not implemented
        try:
            federated_training([])
        except Exception as e:
            self.fail(f"federated_training raised {e}")


class TestEvaluateFederatedModelException(unittest.TestCase):
    @patch("fl.src.fl_trainer.evaluate_security_model")
    def test_evaluate_federated_model_handles_exception(self, mock_eval):
        mock_eval.side_effect = Exception("fail")
        from fl.src import fl_trainer

        results = fl_trainer.evaluate_federated_model(
            global_model=None,
            client_test_paths=[Path("a.csv")],
            encoders=None,
            scaler=None,
            grade_encoder=None,
            base_dataset=None,
        )
        self.assertEqual(results["avg_mse"], float("inf"))
        self.assertEqual(results["std_mse"], 0.0)
        self.assertEqual(results["avg_mae"], float("inf"))
        self.assertEqual(results["avg_r2"], 0.0)


class TestFederatedTrainingBranches(unittest.TestCase):
    @patch("fl.src.fl_trainer.SecurityDataset")
    @patch("fl.src.fl_trainer.SecurityNN")
    @patch("fl.src.fl_trainer.DataLoader")
    @patch("fl.src.fl_trainer._train_local")
    @patch("fl.src.fl_trainer.calculate_model_similarity", return_value=1.0)
    @patch(
        "fl.src.fl_trainer.evaluate_federated_model",
        return_value={"avg_mse": 1, "avg_mae": 2, "avg_r2": 3},
    )
    def test_aggregation_median_and_secure(
        self, mock_eval, mock_sim, mock_train, mock_dl, mock_nn, mock_ds
    ):
        # Setup mocks
        mock_ds.return_value.features.shape = (4, 2)
        mock_ds.return_value.encoders = None
        mock_ds.return_value.scaler = None
        mock_loader = MagicMock()
        mock_loader.dataset = [1, 2, 3]
        mock_dl.return_value = mock_loader
        mock_nn.return_value.state_dict.return_value = {"w": torch.tensor([1.0, 2.0])}
        mock_nn.return_value.to.return_value = mock_nn.return_value
        mock_nn.return_value.load_state_dict.return_value = None
        mock_nn.return_value.parameters.return_value = [torch.tensor([1.0, 2.0])]
        # Median
        from fl.src import fl_trainer

        dataset_paths = [{"train": "a", "test": "b"}, {"train": "c", "test": "d"}]
        with patch(
            "fl.src.fl_trainer.aggregate_median",
            return_value={"w": torch.tensor([1.0, 2.0])},
        ):
            result = fl_trainer.federated_training(
                dataset_paths,
                aggregation="median",
                rounds=1,
                local_epochs=1,
                verbose=False,
            )
            self.assertIn("history", result)
        # Secure
        with patch(
            "fl.src.fl_trainer.aggregate_secure_average",
            return_value={"w": torch.tensor([1.0, 2.0])},
        ):
            result = fl_trainer.federated_training(
                dataset_paths,
                aggregation="secure",
                rounds=1,
                local_epochs=1,
                verbose=False,
            )
            self.assertIn("history", result)

    @patch("fl.src.fl_trainer.SecurityDataset")
    @patch("fl.src.fl_trainer.SecurityNN")
    @patch("fl.src.fl_trainer.DataLoader")
    def test_aggregation_unknown(self, mock_dl, mock_nn, mock_ds):
        mock_ds.return_value.features.shape = (4, 2)
        mock_ds.return_value.encoders = None
        mock_ds.return_value.scaler = None
        mock_dl.return_value = [1, 2]
        mock_nn.return_value.state_dict.return_value = {"w": torch.tensor([1.0, 2.0])}
        mock_nn.return_value.to.return_value = mock_nn.return_value
        mock_nn.return_value.load_state_dict.return_value = None
        from fl.src import fl_trainer

        dataset_paths = [{"train": "a", "test": "b"}]
        with self.assertRaises(ValueError):
            fl_trainer.federated_training(
                dataset_paths,
                aggregation="unknown",
                rounds=1,
                local_epochs=1,
                verbose=False,
            )

    @patch("fl.src.fl_trainer.SecurityDataset")
    @patch("fl.src.fl_trainer.SecurityNN")
    @patch("fl.src.fl_trainer.DataLoader")
    @patch("fl.src.fl_trainer._train_local")
    @patch("fl.src.fl_trainer.calculate_model_similarity", return_value=1.0)
    @patch(
        "fl.src.fl_trainer.evaluate_federated_model",
        return_value={"avg_mse": 1, "avg_mae": 2, "avg_r2": 3},
    )
    def test_final_metrics_empty_history(
        self, mock_eval, mock_sim, mock_train, mock_dl, mock_nn, mock_ds
    ):
        mock_ds.return_value.features.shape = (4, 2)
        mock_ds.return_value.encoders = None
        mock_ds.return_value.scaler = None
        mock_dl.return_value = [1, 2]
        mock_nn.return_value.state_dict.return_value = {"w": torch.tensor([1.0, 2.0])}
        mock_nn.return_value.to.return_value = mock_nn.return_value
        mock_nn.return_value.load_state_dict.return_value = None
        from fl.src import fl_trainer

        # No dataset paths
        result = fl_trainer.federated_training([], verbose=False)
        self.assertEqual(result, {})


class TestRunFederatedExperiment(unittest.TestCase):
    @patch(
        "fl.src.fl_trainer.generate_fl_datasets",
        return_value=[{"train": "a", "test": "b"}],
    )
    @patch(
        "fl.src.fl_trainer.federated_training",
        return_value={
            "history": {"global_mse": [1]},
            "final_metrics": {},
            "config": {},
        },
    )
    @patch("fl.src.fl_trainer.save_federated_results")
    def test_run_federated_experiment_save(self, mock_save, mock_train, mock_gen):
        from fl.src import fl_trainer

        config = fl_trainer.create_federated_experiment_config()
        result = fl_trainer.run_federated_experiment(
            output_dir="/tmp", config=config, save_results=True
        )
        mock_save.assert_called()
        self.assertIn("history", result)

    @patch(
        "fl.src.fl_trainer.generate_fl_datasets",
        return_value=[{"train": "a", "test": "b"}],
    )
    @patch(
        "fl.src.fl_trainer.federated_training",
        return_value={
            "history": {"global_mse": [1]},
            "final_metrics": {},
            "config": {},
        },
    )
    @patch("fl.src.fl_trainer.save_federated_results")
    def test_run_federated_experiment_no_save(self, mock_save, mock_train, mock_gen):
        from fl.src import fl_trainer

        config = fl_trainer.create_federated_experiment_config()
        result = fl_trainer.run_federated_experiment(
            output_dir="", config=config, save_results=False
        )
        mock_save.assert_not_called()
        self.assertIn("history", result)

    @patch(
        "fl.src.fl_trainer.generate_fl_datasets",
        return_value=[{"train": "a", "test": "b"}],
    )
    @patch(
        "fl.src.fl_trainer.federated_training",
        return_value={
            "history": {"global_mse": [1]},
            "final_metrics": {},
            "config": {},
        },
    )
    @patch("fl.src.fl_trainer.save_federated_results")
    def test_run_federated_experiment_default_config(
        self, mock_save, mock_train, mock_gen
    ):
        from fl.src import fl_trainer

        result = fl_trainer.run_federated_experiment(
            output_dir="/tmp", config=None, save_results=True
        )
        self.assertIn("history", result)


class TestMainFunction(unittest.TestCase):
    @patch(
        "fl.src.fl_trainer.run_federated_experiment",
        return_value={"global_mse": [1, 2, 3]},
    )
    @patch("fl.src.fl_trainer.create_federated_experiment_config")
    def test_main_runs(self, mock_config, mock_run):
        from fl.src import fl_trainer

        mock_config.return_value = {
            "num_clients": 2,
            "samples_per_client": 2,
            "rounds": 1,
            "local_epochs": 1,
            "aggregation": "weighted",
            "use_differential_privacy": False,
        }
        with patch("builtins.print") as mock_print:
            fl_trainer.main()
            self.assertTrue(mock_print.called)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
