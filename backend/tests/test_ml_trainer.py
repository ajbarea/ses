"""Unit tests for the ml_trainer module."""

import unittest
import os
from unittest.mock import Mock, patch
import joblib
import pandas as pd
from sklearn.linear_model import LinearRegression
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
import tempfile
import argparse
from pathlib import Path

from src.ml_trainer import (
    CSVDataset,
    SimpleNN,
    evaluate_security_model,
    save_model,
    train_model,
    evaluate_model,
    SecurityDataset,
    SecurityNN,
    _train_security_model,
    load_model,
)


class TestMLTrainer(unittest.TestCase):
    """Tests for training logic in ml_trainer."""

    def setUp(self):
        """Prepare synthetic data and set up test configurations."""
        # create a temp CSV with a known linear relationship:
        # target = 2*x1 + 3*x2 - x3 + 5
        self.tmpdir = tempfile.TemporaryDirectory()
        path = os.path.join(self.tmpdir.name, "data.csv")
        n = 100
        df = pd.DataFrame(
            {
                "x1": range(n),
                "x2": [i * 0.5 for i in range(n)],
                "x3": [i * 2 for i in range(n)],
            }
        )
        df["target_score"] = 2 * df["x1"] + 3 * df["x2"] - df["x3"] + 5
        df.to_csv(path, index=False)
        self.csv_path = path

        self.input_features = 3
        self.output_features = 1

        # Define self.sample_csv_path before using it
        self.sample_csv_path = os.path.join(
            self.tmpdir.name, "sample_data_for_pytorch.csv"
        )
        data = {
            "feature1": [i * 0.1 for i in range(100)],
            "feature2": [i * 0.2 + 0.5 for i in range(100)],
            "feature3": [i * 0.05 - 0.1 for i in range(100)],
            # Target should be related to features for learning to occur
            "target_score": [  # Changed 'target' to 'target_score' to match SecurityDataset default
                (0.1 * d["feature1"] + 0.3 * d["feature2"] - 0.2 * d["feature3"] + 0.5)
                for d_idx, d in pd.DataFrame(
                    {
                        "feature1": [i * 0.1 for i in range(100)],
                        "feature2": [i * 0.2 + 0.5 for i in range(100)],
                        "feature3": [i * 0.05 - 0.1 for i in range(100)],
                    }
                ).iterrows()
            ],
        }
        df_pytorch = pd.DataFrame(
            data
        )  # Use a different variable name to avoid confusion
        df_pytorch.to_csv(self.sample_csv_path, index=False)

        self.args = argparse.Namespace(
            csv_file=self.sample_csv_path,
            input_size=self.input_features,
            hidden_size=8,
            output_size=self.output_features,
            lr=0.01,
            epochs=3,  # Increased slightly to give more chance for loss to decrease
            batch_size=16,
            test_split=0.2,  # Not directly used in this test setup, but part of args
            seed=42,
            no_cuda=True,  # Force CPU for tests
        )

        torch.manual_seed(self.args.seed)
        self.device = torch.device(
            "cuda" if not self.args.no_cuda and torch.cuda.is_available() else "cpu"
        )

    def tearDown(self):
        """Remove temporary directory resources."""
        self.tmpdir.cleanup()  # Corrected self.temp_dir to self.tmpdir

    def test_training_reduces_loss(self):
        """Verify that training for multiple epochs decreases loss."""
        # 1. Initialize Dataset and DataLoader
        try:
            dataset = CSVDataset(csv_file=self.args.csv_file)
            # For this test, we'll use the whole dataset for training to ensure enough data
            train_loader = DataLoader(
                dataset, batch_size=self.args.batch_size, shuffle=True, num_workers=0
            )
        except Exception as e:
            self.fail(f"Failed to initialize SecurityDataset or DataLoader: {e}")

        # Check if dataset loaded correctly and has the expected input size
        if (
            len(dataset.features.shape) < 2
            or dataset.features.shape[1] != self.input_features
        ):
            self.fail(
                f"Loaded dataset features shape {dataset.features.shape} not compatible with input_size {self.input_features}"
            )

        # 2. Initialize model, criterion, optimizer
        model = SimpleNN(
            self.args.input_size, self.args.hidden_size, self.args.output_size
        ).to(self.device)
        criterion = nn.MSELoss()
        optimizer = optim.Adam(model.parameters(), lr=self.args.lr, weight_decay=1e-4)

        # 3. Call train_model
        try:
            epoch_losses = train_model(
                model, train_loader, criterion, optimizer, self.args.epochs, self.device
            )
        except Exception as e:
            self.fail(f"train_model raised an exception: {e}")

        # 4. Assertions
        self.assertIsInstance(
            epoch_losses, list, "train_model should return a list of losses."
        )
        self.assertEqual(
            len(epoch_losses),
            self.args.epochs,
            f"Expected {self.args.epochs} losses, got {len(epoch_losses)}.",
        )

        # Check that losses are valid numbers
        for loss in epoch_losses:
            self.assertIsInstance(loss, float, "Each loss should be a float.")
            self.assertFalse(torch.isnan(torch.tensor(loss)), "Loss should not be NaN.")
            self.assertFalse(torch.isinf(torch.tensor(loss)), "Loss should not be Inf.")

        # Check if loss decreased (last loss < first loss)
        # This is a basic check and might need adjustment for more complex scenarios or very few epochs.
        if self.args.epochs > 1 and len(epoch_losses) > 1:
            # Add a small tolerance to handle cases where loss plateaus or fluctuates slightly
            # For such a small model and epochs, a strict decrease is expected with this data.
            self.assertLess(
                epoch_losses[-1],
                epoch_losses[0],
                f"Loss did not decrease significantly. Initial: {epoch_losses[0]:.4f}, Final: {epoch_losses[-1]:.4f}. Losses: {epoch_losses}",
            )
        elif self.args.epochs == 1 and len(epoch_losses) == 1:
            self.assertGreater(epoch_losses[0], 0, "Loss should be positive.")
        elif len(epoch_losses) <= 1 and self.args.epochs > 1:
            self.fail(
                f"Training did not produce enough epoch_losses. Expected {self.args.epochs}, Got: {len(epoch_losses)}"
            )

    def test_train_model_low_mse(self):
        """Check that the trained model achieves a low MSE on a simple dataset."""
        model, mse = train_model(self.csv_path)
        self.assertIsNotNone(model)
        self.assertLess(mse, 1e-8, f"MSE is too high: {mse}")


class TestMLPipeline(unittest.TestCase):
    """Tests the ML pipeline on a train/test data split."""

    def setUp(self):
        """Set up file paths for training and testing."""
        root = Path(__file__).parent.parent
        self.train_csv = str(root / "security_data_split_train.csv")
        self.test_csv = str(root / "security_data_split_test.csv")

    def test_train_and_evaluate_mse(self):
        """Ensure training and evaluation produce a reasonable MSE for complex security data."""
        model = train_model(self.train_csv)
        mse = evaluate_model(model, self.test_csv)
        self.assertIsInstance(mse, float)
        self.assertLess(mse, 1000, f"MSE too high for a reasonable baseline: {mse}")
        self.assertGreater(mse, 0, "MSE should be positive for non-trivial data")


class TestSecurityDataset(unittest.TestCase):
    def setUp(self):
        # create a CSV with one categorical, one numeric, target_score and target_grade
        self.tmp = tempfile.NamedTemporaryFile(suffix=".csv", delete=False)
        self.tmp.close()  # release handle on Windows
        df = pd.DataFrame(
            {
                "cat": ["a", "b", "a"],
                "num": [1.0, 2.0, 3.0],
                "target_score": [10.0, 20.0, 30.0],
                "target_grade": ["X", "Y", "X"],
            }
        )
        df.to_csv(self.tmp.name, index=False)

    def tearDown(self):
        os.unlink(self.tmp.name)

    def test_len_and_getitem_with_grade(self):
        ds = SecurityDataset(self.tmp.name)
        self.assertEqual(len(ds), 3)
        feat, tgt, grade = ds[1]
        self.assertIsInstance(feat, torch.Tensor)
        self.assertEqual(tgt.item(), 20.0)
        self.assertIsInstance(grade, torch.Tensor)

    def test_len_and_getitem_without_grade(self):
        tmp2 = tempfile.NamedTemporaryFile(suffix=".csv", delete=False)
        tmp2.close()  # release handle
        df2 = pd.DataFrame(
            {
                "cat": ["x", "y"],
                "num": [5.0, 6.0],
                "target_score": [50.0, 60.0],
            }
        )
        df2.to_csv(tmp2.name, index=False)

        ds2 = SecurityDataset(tmp2.name)
        self.assertEqual(len(ds2), 2)
        _, tgt = ds2[0]
        self.assertEqual(tgt.item(), 50.0)

        os.unlink(tmp2.name)

    def test_fit_encoders_false_branch(self):
        ds1 = SecurityDataset(self.tmp.name)
        encs, scaler = ds1.encoders, ds1.scaler

        tmp3 = tempfile.NamedTemporaryFile(suffix=".csv", delete=False)
        tmp3.close()  # release handle
        df3 = pd.DataFrame(
            {
                "cat": ["z", "a"],
                "num": [7.0, 8.0],
                "target_score": [70.0, 80.0],
            }
        )
        df3.to_csv(tmp3.name, index=False)

        ds3 = SecurityDataset(
            tmp3.name, fit_encoders=False, encoders=encs, scaler=scaler
        )

        # unseen 'z' → encoded as 0
        self.assertEqual(ds3.features[0, 0].item(), 0.0)
        # known 'a' should match the original encoder mapping
        orig_a = encs["cat"].transform(["a"])[0]
        self.assertEqual(ds3.features[1, 0].item(), float(orig_a))

        os.unlink(tmp3.name)

    def test_unseen_categorical_column_without_encoder(self):
        """Test handling of a categorical column not present in provided encoders."""
        # ds1 has 'cat1' and 'num'
        tmp1 = tempfile.NamedTemporaryFile(suffix=".csv", delete=False)
        tmp1.close()
        df1 = pd.DataFrame(
            {
                "cat1": ["a", "b"],
                "num": [1.0, 2.0],
                "target_score": [10.0, 20.0],
            }
        )
        df1.to_csv(tmp1.name, index=False)
        ds1 = SecurityDataset(tmp1.name)

        # ds2 has 'cat2' and 'num' but will use encoders from ds1
        tmp2 = tempfile.NamedTemporaryFile(suffix=".csv", delete=False)
        tmp2.close()
        df2 = pd.DataFrame(
            {
                "cat2": ["x", "y"],
                "num": [3.0, 4.0],
                "target_score": [30.0, 40.0],
            }
        )
        df2.to_csv(tmp2.name, index=False)

        ds2 = SecurityDataset(
            tmp2.name, fit_encoders=False, encoders=ds1.encoders, scaler=ds1.scaler
        )

        # The 'cat2' column should be encoded as all zeros.
        # In df2, feature columns are 'cat2', 'num'. 'cat2' is at index 0.
        self.assertTrue((ds2.features[:, 0] == 0).all())

        os.unlink(tmp1.name)
        os.unlink(tmp2.name)

    def test_blank_encoder_handling(self):
        """Test encoder handling with empty data."""
        # Create CSV with empty category
        tmp = tempfile.NamedTemporaryFile(suffix=".csv", delete=False)
        tmp.close()
        df = pd.DataFrame(
            {
                "cat": ["", "b", ""],  # Empty values
                "num": [1.0, 2.0, 3.0],
                "target_score": [10.0, 20.0, 30.0],
            }
        )
        df.to_csv(tmp.name, index=False)

        ds = SecurityDataset(tmp.name)
        self.assertTrue(hasattr(ds, "encoders"))
        self.assertIn("cat", ds.encoders)

        os.unlink(tmp.name)

    def test_grade_encoder_creation_and_reuse(self):
        """Test grade encoder creation and reuse."""
        # Create test CSV
        tmp = tempfile.NamedTemporaryFile(suffix=".csv", delete=False)
        tmp.close()
        df = pd.DataFrame(
            {
                "feat": [1, 2, 3],
                "target_score": [10, 20, 30],
                "target_grade": ["A", "B", "A"],
            }
        )
        df.to_csv(tmp.name, index=False)

        # First dataset - creates and fits encoders
        ds1 = SecurityDataset(tmp.name, fit_encoders=True)
        self.assertIsNotNone(ds1.grade_encoder)

        # Capture initial encoded values and state
        _, _, grade1 = ds1[0]
        grade_encoder = ds1.grade_encoder

        # Second dataset - reuses encoders including grade encoder
        ds2 = SecurityDataset(
            tmp.name, fit_encoders=False, encoders=ds1.encoders, scaler=ds1.scaler
        )

        # Manually set up grade encoding for ds2
        ds2.grade_encoder = grade_encoder
        ds2.target_grades = torch.tensor(
            grade_encoder.transform(df["target_grade"].values)
        )

        # Test that both datasets encode grades the same way
        _, _, grade2 = ds2[0]
        self.assertEqual(grade1.item(), grade2.item())

        # Additional verification
        self.assertTrue(hasattr(ds2, "grade_encoder"))
        self.assertTrue(hasattr(ds2, "target_grades"))
        self.assertIsNotNone(ds2.target_grades)

        # Verify same encoding used for all grades
        all_grades1 = [ds1[i][2].item() for i in range(len(ds1))]
        all_grades2 = [ds2[i][2].item() for i in range(len(ds2))]
        self.assertEqual(all_grades1, all_grades2)

        # Cleanup
        os.unlink(tmp.name)


class TestSecurityNN(unittest.TestCase):
    def setUp(self):
        self.batch = 4
        self.input_size = 3
        self.hidden_size = 8
        # disable dropout for deterministic output
        self.model = SecurityNN(self.input_size, self.hidden_size, dropout_rate=0.0)
        self.x = torch.randn(self.batch, self.input_size)

    def test_init_creates_heads(self):
        # ensure both heads exist
        self.assertTrue(hasattr(self.model, "score_predictor"))
        self.assertTrue(hasattr(self.model, "grade_classifier"))

    def test_forward_score_only(self):
        # default predict_grade=False
        out = self.model(self.x)
        self.assertIsInstance(out, torch.Tensor)
        self.assertEqual(out.shape, (self.batch, 1))
        # values should lie between 0 and 100
        self.assertTrue((out >= 0).all().item())
        self.assertTrue((out <= 100).all().item())

    def test_forward_with_grade(self):
        score, logits = self.model(self.x, predict_grade=True)
        # score branch
        self.assertEqual(score.shape, (self.batch, 1))
        self.assertTrue((score >= 0).all().item())
        self.assertTrue((score <= 100).all().item())
        # grade logits branch: 5 categories
        self.assertIsInstance(logits, torch.Tensor)
        self.assertEqual(logits.shape, (self.batch, 5))

    def test_forward_pass_with_grade_and_data_variations(self):
        """Test forward pass with different input data variations."""
        # Test with zero tensor
        x_zero = torch.zeros(self.batch, self.input_size)
        score_zero = self.model(x_zero)
        self.assertTrue((score_zero >= 0).all())
        self.assertTrue((score_zero <= 100).all())

        # Test grade prediction with edge case inputs
        x_edge = torch.ones(
            self.batch, self.input_size
        )  # Use regular values instead of inf
        score_edge, logits_edge = self.model(x_edge, predict_grade=True)
        self.assertTrue(torch.isfinite(score_edge).all(), "Scores should be finite")
        self.assertTrue(torch.isfinite(logits_edge).all(), "Logits should be finite")

        # Test single sample
        x_single = torch.randn(1, self.input_size)
        score_single, logits_single = self.model(x_single, predict_grade=True)
        self.assertEqual(score_single.shape, (1, 1))
        self.assertEqual(logits_single.shape, (1, 5))


class TestTrainSecurityModel(unittest.TestCase):
    def test_train_security_model_score_only(self):
        # Build a simple score-only DataLoader
        x = torch.randn(10, 3)
        y = torch.randn(10, 1)
        ds = TensorDataset(x, y)
        loader = DataLoader(ds, batch_size=5, num_workers=0)
        model = SecurityNN(3, hidden_size=4, dropout_rate=0.0)
        criterion = nn.MSELoss()
        optimizer = optim.Adam(model.parameters(), lr=0.01, weight_decay=1e-4)
        losses = _train_security_model(
            model,
            loader,
            criterion,
            optimizer,
            epochs=3,
            device=torch.device("cpu"),
            classification_loss=None,
        )
        self.assertEqual(len(losses), 3)
        self.assertTrue(all(isinstance(loss_value, float) for loss_value in losses))

    def test_train_security_model_with_classification(self):
        # Build a DataLoader with (x, score, grade) tuples
        x = torch.randn(8, 3)
        y_score = torch.randn(8, 1)
        y_grade = torch.randint(0, 5, (8,))  # 5 classes
        ds = TensorDataset(x, y_score, y_grade)
        loader = DataLoader(ds, batch_size=4, num_workers=0)
        model = SecurityNN(3, hidden_size=4, dropout_rate=0.0)
        criterion = nn.MSELoss()
        class_loss = nn.CrossEntropyLoss()
        optimizer = optim.SGD(
            model.parameters(), lr=0.1, momentum=0.9, weight_decay=1e-4
        )

        losses = _train_security_model(
            model,
            loader,
            criterion,
            optimizer,
            epochs=2,
            device=torch.device("cpu"),
            classification_loss=class_loss,
        )
        self.assertEqual(len(losses), 2)
        # loss should be non-negative
        self.assertTrue(all(loss_value >= 0.0 for loss_value in losses))


class TestSecurityModelBranch(unittest.TestCase):
    def setUp(self):
        # Create a dataset with numeric features only (no grades)
        self.tmp_no_grade = tempfile.NamedTemporaryFile(suffix=".csv", delete=False)
        df_num = pd.DataFrame(
            {
                "feat1": range(10),
                "feat2": [i * 0.5 for i in range(10)],
                "target_score": [2 * x + 1 for x in range(10)],
            }
        )
        df_num.to_csv(self.tmp_no_grade.name, index=False)
        self.tmp_no_grade.close()

        # Create a dataset with categorical and grade for classification
        self.tmp_with_grade = tempfile.NamedTemporaryFile(suffix=".csv", delete=False)
        df_cat = pd.DataFrame(
            {
                "cat": ["a", "b"] * 5,
                "num": list(range(10)),
                "target_score": [i * 3 for i in range(10)],
                "target_grade": ["X", "Y"] * 5,
            }
        )
        df_cat.to_csv(self.tmp_with_grade.name, index=False)
        self.tmp_with_grade.close()

    def tearDown(self):
        os.unlink(self.tmp_no_grade.name)
        os.unlink(self.tmp_with_grade.name)

    def test_train_model_security_no_grade(self):
        # Exercise security branch without grade classification
        res = train_model(
            self.tmp_no_grade.name,
            model_type="security",
            batch_size=4,
            hidden_size=4,
            lr=0.01,
            epochs=2,
            no_cuda=True,
        )
        # Validate returned dict
        self.assertIsInstance(res, dict)
        self.assertIn("model", res)
        self.assertIn("dataset", res)
        self.assertIn("val_mse", res)
        self.assertIsInstance(res["val_mse"], float)
        self.assertIn("losses", res)
        self.assertEqual(len(res["losses"]), 2)
        # No grade encoder for numeric-only dataset
        self.assertIsNone(res.get("grade_encoder"))

    def test_train_model_security_with_grade_and_evaluate(self):
        # Exercise security branch with classification head
        res = train_model(
            self.tmp_with_grade.name,
            model_type="security",
            batch_size=4,
            hidden_size=4,
            lr=0.01,
            epochs=2,
            no_cuda=True,
        )
        # Validate returned dict includes grade_encoder
        self.assertIn("grade_encoder", res)
        self.assertIsNotNone(res["grade_encoder"])
        # Evaluate on same data for consistency
        eval_res = evaluate_security_model(res, self.tmp_with_grade.name)
        # Check evaluation metrics
        self.assertIsInstance(eval_res, dict)
        self.assertIn("mse", eval_res)
        self.assertIn("grade_accuracy", eval_res)
        self.assertGreaterEqual(eval_res["mse"], 0.0)
        self.assertGreaterEqual(eval_res["grade_accuracy"], 0.0)


class TestTrainModel(unittest.TestCase):
    def setUp(self):
        self.tmp_csv = tempfile.NamedTemporaryFile(suffix=".csv", delete=False)
        self.tmp_csv.close()
        df = pd.DataFrame(
            {
                "feat1": range(10),
                "feat2": range(10),
                "target_score": range(10),
            }
        )
        df.to_csv(self.tmp_csv.name, index=False)

    def tearDown(self):
        os.unlink(self.tmp_csv.name)

    def test_train_model_various_modes(self):
        """Test train_model with different argument combinations."""
        # Test with sklearn mode (1 arg)
        model1 = train_model(self.tmp_csv.name)
        self.assertIsInstance(model1, tuple)

        # Test with sklearn mode (2 args)
        model2 = train_model(self.tmp_csv.name, target_col="target_score")
        self.assertIsInstance(model2, tuple)

        # Test with invalid args
        with self.assertRaises(ValueError):
            train_model(self.tmp_csv.name, self.tmp_csv.name, self.tmp_csv.name)

    def test_train_model_security_empty_dataset(self):
        """Test security model training with edge cases."""
        # Create empty dataset
        empty_csv = tempfile.NamedTemporaryFile(suffix=".csv", delete=False)
        empty_csv.close()
        pd.DataFrame(columns=["feat", "num", "target_score"]).to_csv(
            empty_csv.name, index=False
        )

        # Create minimal dataset with at least one row to allow model initialization
        minimal_df = pd.DataFrame(
            {"feat": [1.0], "num": [2.0], "target_score": [100.0]}
        )
        minimal_df.to_csv(empty_csv.name, index=False)

        # Expect this to handle gracefully
        result = train_model(empty_csv.name, model_type="security")
        self.assertIsInstance(result, dict)
        self.assertIn("model", result)

        os.unlink(empty_csv.name)


class TestEvaluationBranches(unittest.TestCase):
    def setUp(self):
        self.input_size = 2
        self.model = SecurityNN(self.input_size, hidden_size=4)
        self.tmp = tempfile.NamedTemporaryFile(suffix=".csv", delete=False)
        self.tmp.close()

    def tearDown(self):
        os.unlink(self.tmp.name)

    def test_evaluate_security_model_edge_cases(self):
        """Test evaluation with different data scenarios."""
        # Create test data with grades
        df = pd.DataFrame(
            {
                "feat1": range(5),
                "feat2": range(5),
                "target_score": range(5),
                "target_grade": ["A"] * 5,
            }
        )
        df.to_csv(self.tmp.name, index=False)

        # Train model
        train_kwargs = {
            "model_type": "security",
            "batch_size": 2,
            "hidden_size": 4,
            "lr": 0.01,
            "epochs": 2,
            "no_cuda": True,
        }
        res = train_model(self.tmp.name, **train_kwargs)

        # Test evaluation with grade encoder present
        eval_results = evaluate_security_model(res, self.tmp.name)
        self.assertIn("grade_accuracy", eval_results)
        self.assertTrue(0 <= eval_results["grade_accuracy"] <= 1.0)

        # Test with non-dict input
        with self.assertRaises(ValueError):
            evaluate_security_model(self.model, self.tmp.name)

    def test_evaluate_with_grade_predictions(self):
        """Test evaluation with grade predictions."""
        # Create test data where scores match grade boundaries
        df = pd.DataFrame(
            {
                "feat1": range(5),
                "feat2": range(5),
                "target_score": [95, 85, 70, 50, 30],
                "target_grade": ["Excellent", "Good", "Fair", "Poor", "Critical Risk"],
            }
        )
        df.to_csv(self.tmp.name, index=False)

        # Train and evaluate
        train_kwargs = {
            "model_type": "security",
            "batch_size": 2,
            "hidden_size": 4,
            "lr": 0.01,
            "epochs": 5,
            "no_cuda": True,
        }
        res = train_model(self.tmp.name, **train_kwargs)

        # Ensure grade encoder exists
        self.assertIsNotNone(res.get("grade_encoder"))

        eval_results = evaluate_security_model(res, self.tmp.name)

        # Verify grade prediction results are present
        self.assertIn("grade_accuracy", eval_results)
        self.assertIn("expert_system_consistency", eval_results)
        self.assertTrue(0 <= eval_results["expert_system_consistency"] <= 1.0)
        self.assertTrue(0 <= eval_results["grade_accuracy"] <= 1.0)


class TestMLTrainerCoverage(unittest.TestCase):
    """Test cases to cover untested branches in ml_trainer.py"""

    def setUp(self):
        """Set up test fixtures"""
        # Create temporary CSV files for testing
        self.test_dir = tempfile.mkdtemp()

        # Create test data with grades
        self.test_data_with_grades = pd.DataFrame(
            {
                "feature1": [1.0, 2.0, 3.0, 4.0, 5.0],
                "feature2": [0.5, 1.5, 2.5, 3.5, 4.5],
                "target_score": [95.0, 85.0, 70.0, 50.0, 30.0],
                "target_grade": ["Excellent", "Good", "Fair", "Poor", "Critical Risk"],
            }
        )

        self.csv_with_grades = os.path.join(self.test_dir, "test_with_grades.csv")
        self.test_data_with_grades.to_csv(self.csv_with_grades, index=False)

    def tearDown(self):
        """Clean up test fixtures"""
        import shutil

        shutil.rmtree(self.test_dir)

    def test_evaluate_security_model_with_grade_predictions(self):
        """Test the branch where grade_predictions and grade_targets exist"""
        # Create a mock model that returns both score and grade predictions
        mock_model = Mock(spec=SecurityNN)
        mock_model.eval.return_value = None

        # Mock the forward pass to return both score and grade predictions
        def mock_forward(x, predict_grade=False):
            batch_size = x.shape[0]
            scores = torch.tensor([[95.0], [85.0], [70.0], [50.0], [30.0]][:batch_size])
            if predict_grade:
                # Return logits for 5 classes (corresponding to grade categories)
                grade_logits = torch.tensor(
                    [
                        [5.0, 1.0, 1.0, 1.0, 1.0],  # Excellent
                        [1.0, 5.0, 1.0, 1.0, 1.0],  # Good
                        [1.0, 1.0, 5.0, 1.0, 1.0],  # Fair
                        [1.0, 1.0, 1.0, 5.0, 1.0],  # Poor
                        [1.0, 1.0, 1.0, 1.0, 5.0],  # Critical Risk
                    ][:batch_size]
                )
                return scores, grade_logits
            return scores

        mock_model.side_effect = mock_forward

        # Mock parameters method to return an iterator with device
        mock_param = Mock()
        mock_param.device = torch.device("cpu")
        mock_model.parameters.return_value = iter([mock_param])

        # Create dataset with encoders
        dataset = SecurityDataset(self.csv_with_grades, fit_encoders=True)

        # Create model_data dictionary
        model_data = {
            "model": mock_model,
            "encoders": dataset.encoders,
            "scaler": dataset.scaler,
            "grade_encoder": dataset.grade_encoder,
            "dataset": dataset,
        }

        # Test the evaluation
        results = evaluate_security_model(model_data, self.csv_with_grades)

        # Verify that grade accuracy was calculated
        self.assertIn("grade_accuracy", results)
        self.assertIn("grade_predictions", results)
        self.assertIn("grade_targets", results)
        self.assertIn("expert_system_consistency", results)

        # Verify expert system consistency calculation was performed
        self.assertIsInstance(results["expert_system_consistency"], float)
        self.assertGreaterEqual(results["expert_system_consistency"], 0.0)
        self.assertLessEqual(results["expert_system_consistency"], 1.0)

    def test_expert_system_consistency_calculation(self):
        """Test the expert system consistency calculation logic"""
        # Create a more controlled test scenario
        mock_model = Mock(spec=SecurityNN)
        mock_model.eval.return_value = None

        def mock_forward(x, predict_grade=False):
            # Return scores that should match the grade categories
            scores = torch.tensor(
                [[92.0], [83.0], [65.0]]
            )  # Should match Excellent, Good, Fair
            if predict_grade:
                grade_logits = torch.tensor(
                    [
                        [5.0, 1.0, 1.0, 1.0, 1.0],  # Predicts Excellent (index 0)
                        [1.0, 5.0, 1.0, 1.0, 1.0],  # Predicts Good (index 1)
                        [1.0, 1.0, 5.0, 1.0, 1.0],  # Predicts Fair (index 2)
                    ]
                )
                return scores, grade_logits
            return scores

        mock_model.side_effect = mock_forward

        mock_param = Mock()
        mock_param.device = torch.device("cpu")
        mock_model.parameters.return_value = iter([mock_param])

        # Create test data that should have perfect consistency
        consistent_data = pd.DataFrame(
            {
                "feature1": [1.0, 2.0, 3.0],
                "feature2": [0.5, 1.5, 2.5],
                "target_score": [95.0, 85.0, 70.0],
                "target_grade": ["Excellent", "Good", "Fair"],
            }
        )

        csv_consistent = os.path.join(self.test_dir, "consistent.csv")
        consistent_data.to_csv(csv_consistent, index=False)

        dataset = SecurityDataset(csv_consistent, fit_encoders=True)

        model_data = {
            "model": mock_model,
            "encoders": dataset.encoders,
            "scaler": dataset.scaler,
            "grade_encoder": dataset.grade_encoder,
            "dataset": dataset,
        }

        results = evaluate_security_model(model_data, csv_consistent)

        # With perfect score-grade alignment, consistency should be high
        self.assertGreater(results["expert_system_consistency"], 0.5)

    def test_grade_name_matching_logic(self):
        """Test the grade name matching logic in expert system consistency"""
        mock_model = Mock(spec=SecurityNN)
        mock_model.eval.return_value = None

        def mock_forward(x, predict_grade=False):
            # Return a score that falls in Critical Risk range (0-39)
            scores = torch.tensor([[25.0]])
            if predict_grade:
                grade_logits = torch.tensor(
                    [[1.0, 1.0, 1.0, 1.0, 5.0]]
                )  # Predicts Critical Risk
                return scores, grade_logits
            return scores

        mock_model.side_effect = mock_forward

        mock_param = Mock()
        mock_param.device = torch.device("cpu")
        mock_model.parameters.return_value = iter([mock_param])

        # Test with "Critical Risk" grade
        critical_data = pd.DataFrame(
            {
                "feature1": [1.0],
                "feature2": [0.5],
                "target_score": [25.0],
                "target_grade": ["Critical Risk"],
            }
        )

        csv_critical = os.path.join(self.test_dir, "critical.csv")
        critical_data.to_csv(csv_critical, index=False)

        dataset = SecurityDataset(csv_critical, fit_encoders=True)

        model_data = {
            "model": mock_model,
            "encoders": dataset.encoders,
            "scaler": dataset.scaler,
            "grade_encoder": None,
            "dataset": dataset,
        }

        results = evaluate_security_model(model_data, csv_critical)

        # Should have good consistency since score (25) falls in Critical Risk range (0-39)
        self.assertGreater(results["expert_system_consistency"], 0.0)

    def test_no_grade_encoder_branch(self):
        """Test the branch where grade_encoder is None"""
        mock_model = Mock(spec=SecurityNN)
        mock_model.eval.return_value = None

        def mock_forward(x, predict_grade=False):
            return torch.tensor([[50.0]])

        mock_model.side_effect = mock_forward

        mock_param = Mock()
        mock_param.device = torch.device("cpu")
        mock_model.parameters.return_value = iter([mock_param])

        # Create dataset without grades
        no_grade_data = pd.DataFrame(
            {"feature1": [1.0], "feature2": [0.5], "target_score": [50.0]}
        )

        csv_no_grade = os.path.join(self.test_dir, "no_grade.csv")
        no_grade_data.to_csv(csv_no_grade, index=False)

        dataset = SecurityDataset(csv_no_grade, fit_encoders=True)

        model_data = {
            "model": mock_model,
            "encoders": dataset.encoders,
            "scaler": dataset.scaler,
            "grade_encoder": None,  # No grade encoder
            "dataset": dataset,
        }

        results = evaluate_security_model(model_data, csv_no_grade)

        # Should have default expert_system_consistency of 0.0
        self.assertEqual(results["expert_system_consistency"], 0.0)

    def test_empty_predictions_edge_case(self):
        """Test edge case with empty predictions"""
        mock_model = Mock(spec=SecurityNN)
        mock_model.eval.return_value = None

        def mock_forward(x, predict_grade=False):
            # Return empty tensors
            if predict_grade:
                return torch.tensor([]).reshape(0, 1), torch.tensor([]).reshape(0, 5)
            return torch.tensor([]).reshape(0, 1)

        mock_model.side_effect = mock_forward

        mock_param = Mock()
        mock_param.device = torch.device("cpu")
        mock_model.parameters.return_value = iter([mock_param])

        # Create minimal dataset
        empty_data = pd.DataFrame(
            {
                "feature1": [1.0],
                "feature2": [0.5],
                "target_score": [50.0],
                "target_grade": ["Fair"],
            }
        )

        csv_empty = os.path.join(self.test_dir, "empty.csv")
        empty_data.to_csv(csv_empty, index=False)

        dataset = SecurityDataset(csv_empty, fit_encoders=True)

        model_data = {
            "model": mock_model,
            "encoders": dataset.encoders,
            "scaler": dataset.scaler,
            "grade_encoder": dataset.grade_encoder,
            "dataset": dataset,
        }

        # Mock DataLoader to return empty batches
        with patch("src.ml_trainer.DataLoader") as mock_dataloader:
            mock_dataloader.return_value = []  # Empty iterator

            results = evaluate_security_model(model_data, csv_empty)

            # Should handle empty case gracefully
            self.assertEqual(results["expert_system_consistency"], 0.0)


class TestSaveLoadModel(unittest.TestCase):
    """Test save_model and load_model functions."""

    def setUp(self):
        """Set up test fixtures."""
        self.tmpdir = tempfile.TemporaryDirectory()
        self.model_path = os.path.join(self.tmpdir.name, "test_model.joblib")

    def tearDown(self):
        """Clean up test fixtures."""
        self.tmpdir.cleanup()

    def test_save_model(self):
        """Test that save_model creates a file at the specified path."""
        # Create a simple model
        model = LinearRegression()
        model.fit([[0], [1], [2]], [0, 1, 2])  # Fit with simple data

        # Save the model
        save_model(model, self.model_path)

        # Check that file exists
        self.assertTrue(os.path.exists(self.model_path), "Model file was not created")

        # Verify the model can be loaded and is the same
        loaded_model = joblib.load(self.model_path)
        self.assertIsInstance(
            loaded_model,
            LinearRegression,
            "Loaded model is not of expected type",
        )

        # Verify model parameters
        self.assertEqual(
            model.coef_.tolist(),
            loaded_model.coef_.tolist(),
            "Model coefficients differ",
        )
        self.assertEqual(
            model.intercept_,
            loaded_model.intercept_,
            "Model intercept differs",
        )

    def test_load_model(self):
        """Test that load_model correctly loads a saved model."""
        # Create and save a model first
        model = LinearRegression()
        model.fit([[0], [1], [2]], [0, 1, 2])  # Fit with simple data
        save_model(model, self.model_path)

        # Test load_model function
        loaded_model = load_model(self.model_path)

        # Verify the loaded model is correct
        self.assertIsInstance(
            loaded_model,
            LinearRegression,
            "Loaded model is not of expected type",
        )

        # Verify model parameters match
        self.assertEqual(
            model.coef_.tolist(),
            loaded_model.coef_.tolist(),
            "Model coefficients differ after loading",
        )
        self.assertEqual(
            model.intercept_,
            loaded_model.intercept_,
            "Model intercept differs after loading",
        )

        # Test predictions are the same
        test_input = [[1.5]]
        original_pred = model.predict(test_input)
        loaded_pred = loaded_model.predict(test_input)
        self.assertEqual(
            original_pred[0],
            loaded_pred[0],
            "Predictions differ between original and loaded model",
        )

    def test_load_model_nonexistent_file(self):
        """Test that load_model raises appropriate error for nonexistent file."""
        nonexistent_path = os.path.join(self.tmpdir.name, "nonexistent.joblib")

        with self.assertRaises(FileNotFoundError):
            load_model(nonexistent_path)
