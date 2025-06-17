"""Unit tests for the ml_trainer module."""

import unittest
import os
import pandas as pd
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader
import tempfile
import argparse
from pathlib import Path

from src.ml_trainer import (
    CSVDataset,
    SimpleNN,
    train_model,
    evaluate_model,
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
                dataset, batch_size=self.args.batch_size, shuffle=True
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
        optimizer = optim.Adam(model.parameters(), lr=self.args.lr)

        # 3. Call train_model
        try:
            # Suppress print statements from train_model during test
            # by redirecting stdout temporarily for the call if desired, or just let them print.
            # For now, allow prints as they can be useful for debugging.
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
            self.assertTrue(epoch_losses[0] > 0, "Loss should be positive.")
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
        """Ensure training and evaluation produce a sufficiently low MSE."""
        model = train_model(self.train_csv)
        mse = evaluate_model(model, self.test_csv)
        # Expect exact or near-exact fit since targets are constant or linear
        self.assertIsInstance(mse, float)
        self.assertLess(mse, 1e-6, f"MSE too high: {mse}")


if __name__ == "__main__":
    unittest.main()
