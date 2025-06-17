"""This module provides training and evaluation routines for security-related ML tasks."""

import argparse
import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
from sklearn.linear_model import LinearRegression
from sklearn.metrics import mean_squared_error, accuracy_score
from sklearn.preprocessing import LabelEncoder, StandardScaler
import joblib
import numpy as np


class SecurityDataset(Dataset):
    """Loads and preprocesses security metrics for training."""

    def __init__(
        self,
        csv_file: str,
        target_col: str = "target_score",
        fit_encoders=True,
        encoders=None,
        scaler=None,
        grade_encoder=None,
    ):
        df = pd.read_csv(csv_file)

        # Separate features and targets
        self.target_col = target_col
        feature_cols = [col for col in df.columns if not col.startswith("target_")]

        # Handle categorical variables
        categorical_cols = df[feature_cols].select_dtypes(include=["object"]).columns
        numerical_cols = df[feature_cols].select_dtypes(include=["number"]).columns

        if fit_encoders:
            self.encoders = {}
            self.scaler = StandardScaler()

            # Encode categorical variables
            df_encoded = df[feature_cols].copy()
            for col in categorical_cols:
                le = LabelEncoder()
                df_encoded[col] = le.fit_transform(df[col].astype(str))
                self.encoders[col] = le

            # Scale numerical features
            df_encoded[numerical_cols] = self.scaler.fit_transform(df[numerical_cols])

        else:
            self.encoders = encoders
            self.scaler = scaler

            # Apply existing encoders
            df_encoded = df[feature_cols].copy()
            for col in categorical_cols:
                if col in self.encoders:
                    # Handle unseen categories gracefully
                    df_encoded[col] = (
                        df[col]
                        .astype(str)
                        .map(
                            lambda x: (
                                self.encoders[col].transform([x])[0]
                                if x in self.encoders[col].classes_
                                else 0
                            )
                        )
                    )
                else:
                    df_encoded[col] = 0

            # Apply existing scaler
            df_encoded[numerical_cols] = self.scaler.transform(df[numerical_cols])

        self.features = torch.tensor(df_encoded.values, dtype=torch.float32)
        self.targets = torch.tensor(
            df[target_col].values, dtype=torch.float32
        ).unsqueeze(1)

        # Store target grades for classification if available
        if "target_grade" in df.columns:
            if fit_encoders:
                self.grade_encoder = LabelEncoder()
                self.target_grades = torch.tensor(
                    self.grade_encoder.fit_transform(df["target_grade"]),
                    dtype=torch.long,
                )
            else:
                self.grade_encoder = grade_encoder
                if self.grade_encoder:
                    self.target_grades = torch.tensor(
                        self.grade_encoder.transform(df["target_grade"]),
                        dtype=torch.long,
                    )
                else:
                    self.target_grades = None
        else:
            self.target_grades = None

    def __len__(self):
        return len(self.targets)

    def __getitem__(self, idx):
        if self.target_grades is not None:
            return self.features[idx], self.targets[idx], self.target_grades[idx]
        return self.features[idx], self.targets[idx]


class SecurityNN(nn.Module):
    """A PyTorch module for predicting security scores and optionally classifying security grades."""

    def __init__(
        self, input_size: int, hidden_size: int = 64, dropout_rate: float = 0.2
    ):
        super().__init__()
        self.score_predictor = nn.Sequential(
            nn.Linear(input_size, hidden_size),
            nn.LayerNorm(hidden_size),
            nn.ReLU(),
            nn.Dropout(dropout_rate),
            nn.Linear(hidden_size, hidden_size // 2),
            nn.LayerNorm(hidden_size // 2),
            nn.ReLU(),
            nn.Dropout(dropout_rate),
            nn.Linear(hidden_size // 2, 1),
            nn.Sigmoid(),  # Output between 0 and 1, will be scaled to 0-100
        )

        # Optional classification head for grades
        self.grade_classifier = nn.Sequential(
            nn.Linear(input_size, hidden_size),
            nn.ReLU(),
            nn.Dropout(dropout_rate),
            nn.Linear(hidden_size, 5),
        )

    def forward(self, x: torch.Tensor, predict_grade: bool = False):
        score = self.score_predictor(x) * 100  # Scale to 0-100
        if predict_grade:
            grade_logits = self.grade_classifier(x)
            return score, grade_logits
        return score


class SimpleNN(nn.Module):
    """A simple feed-forward network with one hidden layer."""

    def __init__(self, input_size: int, hidden_size: int, output_size: int):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(input_size, hidden_size),
            nn.ReLU(),
            nn.Linear(hidden_size, output_size),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)


class CSVDataset(Dataset):
    """Loads features and a target column from a CSV for training."""

    def __init__(self, csv_file: str, target_col: str = "target_score"):
        df = pd.read_csv(csv_file)
        self.features = torch.tensor(
            df.drop(columns=[target_col]).values, dtype=torch.float32
        )
        self.targets = torch.tensor(
            df[target_col].values, dtype=torch.float32
        ).unsqueeze(1)

    def __len__(self):
        return len(self.targets)

    def __getitem__(self, idx):
        return self.features[idx], self.targets[idx]


def _train_security_model(
    model: nn.Module,
    loader: DataLoader,
    criterion,
    optimizer,
    epochs: int,
    device: torch.device,
    classification_loss=None,
) -> list:
    """Train a SecurityNN with optional grade classification."""
    model.to(device)
    losses = []

    for epoch in range(epochs):
        epoch_loss = 0.0
        model.train()

        for batch in loader:
            if len(batch) == 3:  # Has grade classification
                x, y_score, y_grade = batch
                x, y_score, y_grade = (
                    x.to(device),
                    y_score.to(device),
                    y_grade.to(device),
                )

                optimizer.zero_grad()
                score_pred, grade_pred = model(x, predict_grade=True)

                score_loss = criterion(score_pred, y_score)
                grade_loss = (
                    classification_loss(grade_pred, y_grade)
                    if classification_loss
                    else 0
                )

                total_loss = score_loss + 0.3 * grade_loss  # Weight the losses
                total_loss.backward()
            else:  # Only score prediction
                x, y_score = batch
                x, y_score = x.to(device), y_score.to(device)

                optimizer.zero_grad()
                score_pred = model(x)

                total_loss = criterion(score_pred, y_score)
                total_loss.backward()

            optimizer.step()
            epoch_loss += total_loss.item() * x.size(0)

        avg_loss = epoch_loss / len(loader.dataset)
        losses.append(avg_loss)

        if (epoch + 1) % 10 == 0:
            print(f"Epoch {epoch + 1}/{epochs}, Loss: {avg_loss:.4f}")

    return losses


def _train_torch_model(
    model: nn.Module,
    loader: torch.utils.data.DataLoader,
    criterion,
    optimizer,
    epochs: int,
    device: torch.device,
) -> list:
    """Train a generic PyTorch model and return epoch losses."""
    model.to(device)
    losses = []
    for _ in range(epochs):
        epoch_loss = 0.0
        for x, y in loader:
            x, y = x.to(device), y.to(device)
            optimizer.zero_grad()
            out = model(x)
            loss = criterion(out, y)
            loss.backward()
            optimizer.step()
            epoch_loss += loss.item() * x.size(0)
        losses.append(epoch_loss / len(loader.dataset))
    return losses


def _train_sklearn_model(csv_file: str, target_col: str = "target_score"):
    """Train a linear regression model on CSV and return (model, MSE)."""
    df = pd.read_csv(csv_file)
    # Select numeric feature columns, drop target and any grade column
    X_df = df.drop(columns=[target_col, "target_grade"], errors="ignore")
    X_df = X_df.select_dtypes(include=["number"])
    # Prepare data arrays
    X = X_df.values
    y = df[target_col].values
    model = LinearRegression().fit(X, y)
    preds = model.predict(X)
    return model, mean_squared_error(y, preds)


def _load_xy(csv_file: str, target_col: str = "target_score"):
    """Load X and y from a CSV, removing the target column and ignoring 'target_grade'."""
    df = pd.read_csv(csv_file)
    y = df[target_col]
    X = df.drop(columns=[target_col, "target_grade"], errors="ignore")
    X = X.select_dtypes(include="number")
    return X, y


def train_model(*args, **kwargs):
    """Train either a PyTorch, SecurityNN, or sklearn model depending on arguments."""
    if len(args) == 6:
        # PyTorch training: (model, loader, criterion, optimizer, epochs, device)
        model, loader, criterion, optimizer, epochs, device = args
        if hasattr(model, "score_predictor"):  # SecurityNN
            classification_loss = (
                nn.CrossEntropyLoss()
                if any(len(batch) == 3 for batch in loader)
                else None
            )
            return _train_security_model(
                model, loader, criterion, optimizer, epochs, device, classification_loss
            )
        else:  # Regular NN
            return _train_torch_model(
                model, loader, criterion, optimizer, epochs, device
            )

    elif kwargs.get("model_type") == "security":
        # Security model training
        train_csv = args[0] if args else kwargs["train_csv"]
        target_col = (
            args[1] if len(args) > 1 else kwargs.get("target_col", "target_score")
        )

        # Create security dataset with preprocessing
        dataset = SecurityDataset(train_csv, target_col, fit_encoders=True)

        # Handle empty dataset
        if len(dataset) == 0:
            print("Warning: Dataset is empty. Creating minimal training setup.")
            model = SecurityNN(1, kwargs.get("hidden_size", 64))  # Minimal model
            return {
                "model": model,
                "dataset": dataset,
                "val_mse": float("inf"),
                "losses": [],
                "encoders": dataset.encoders,
                "scaler": dataset.scaler,
                "grade_encoder": getattr(dataset, "grade_encoder", None),
            }

        # Split for validation
        train_size = int(0.8 * len(dataset))
        val_size = len(dataset) - train_size

        # Ensure at least one sample in each split if dataset is very small
        if train_size == 0:
            train_size = 1
            val_size = max(0, len(dataset) - 1)
        elif val_size == 0 and len(dataset) > 1:
            val_size = 1
            train_size = len(dataset) - 1

        train_ds, val_ds = torch.utils.data.random_split(
            dataset, [train_size, val_size]
        )

        # Use smaller batch size for small datasets
        batch_size = min(kwargs.get("batch_size", 32), max(1, len(dataset) // 4))

        train_loader = DataLoader(train_ds, batch_size=batch_size, shuffle=True)
        val_loader = (
            DataLoader(val_ds, batch_size=batch_size, shuffle=False)
            if val_size > 0
            else None
        )

        # Create model
        input_size = dataset.features.shape[1]
        model = SecurityNN(input_size, kwargs.get("hidden_size", 64))

        # Training setup
        device = torch.device(
            "cuda"
            if torch.cuda.is_available() and not kwargs.get("no_cuda", False)
            else "cpu"
        )
        criterion = nn.MSELoss()
        optimizer = torch.optim.Adam(model.parameters(), lr=kwargs.get("lr", 0.001))

        # Train
        losses = train_model(
            model, train_loader, criterion, optimizer, kwargs.get("epochs", 50), device
        )

        # Evaluate
        model.eval()
        val_loss = 0
        val_predictions = []
        val_targets = []

        if val_loader:
            with torch.no_grad():
                for batch in val_loader:
                    if len(batch) == 3:
                        x, y_score, y_grade = batch
                    else:
                        x, y_score = batch

                    x, y_score = x.to(device), y_score.to(device)
                    pred = model(x)
                    val_loss += criterion(pred, y_score).item()

                    val_predictions.extend(pred.cpu().numpy())
                    val_targets.extend(y_score.cpu().numpy())

        val_mse = (
            mean_squared_error(val_targets, val_predictions)
            if val_predictions
            else float("inf")
        )
        print(f"Validation MSE: {val_mse:.4f}")

        return {
            "model": model,
            "dataset": dataset,
            "val_mse": val_mse,
            "losses": losses,
            "encoders": dataset.encoders,
            "scaler": dataset.scaler,
            "grade_encoder": getattr(dataset, "grade_encoder", None),
        }

    elif len(args) in [1, 2]:
        # Sklearn training: (train_csv, target_col)
        train_csv = args[0]
        target_col = (
            args[1] if len(args) == 2 else kwargs.get("target_col", "target_score")
        )
        return _train_sklearn_model(train_csv, target_col=target_col)
    else:
        raise ValueError(
            f"Invalid number of arguments: {len(args)}. Expected 1-2 for sklearn or 6 for PyTorch."
        )


def evaluate_model(
    model_or_tuple, test_csv: str, target_col: str = "target_score"
) -> float:
    """Compute MSE on test CSV for a scikit-learn model."""
    model = model_or_tuple[0] if isinstance(model_or_tuple, tuple) else model_or_tuple
    X_test, y_test = _load_xy(test_csv, target_col)
    preds = model.predict(X_test)
    return mean_squared_error(y_test, preds)


def evaluate_security_model(
    model_data, test_csv: str, target_col: str = "target_score"
):
    """Evaluate a trained SecurityNN (and optional grade classifier) on test data."""
    if isinstance(model_data, dict):
        model = model_data["model"]
        encoders = model_data["encoders"]
        scaler = model_data["scaler"]
        grade_encoder = model_data.get("grade_encoder")
    else:
        raise ValueError(
            "Expected model_data to be a dictionary from security model training"
        )

    # If grade_encoder isn't in model_data, try to get it from the dataset object
    if grade_encoder is None:
        grade_encoder = getattr(model_data.get("dataset"), "grade_encoder", None)

    # Create test dataset using fitted encoders
    test_dataset = SecurityDataset(
        test_csv,
        target_col,
        fit_encoders=False,
        encoders=encoders,
        scaler=scaler,
        grade_encoder=grade_encoder,
    )

    test_loader = DataLoader(test_dataset, batch_size=32, shuffle=False)
    device = next(model.parameters()).device

    model.eval()
    predictions = []
    targets = []
    grade_predictions = []
    grade_targets = []

    with torch.no_grad():
        for batch in test_loader:
            if len(batch) == 3:
                x, y_score, y_grade = batch
                grade_targets.extend(y_grade.cpu().numpy())
            else:
                x, y_score = batch

            x, y_score = x.to(device), y_score.to(device)

            if len(batch) == 3 and grade_encoder:
                score_pred, grade_pred = model(x, predict_grade=True)
                grade_predictions.extend(torch.argmax(grade_pred, dim=1).cpu().numpy())
            else:
                score_pred = model(x)

            predictions.extend(score_pred.cpu().numpy())
            targets.extend(y_score.cpu().numpy())

    # Handle empty test set
    if not targets:
        return {
            "mse": float("inf"),
            "mae": float("inf"),
            "rmse": float("inf"),
            "r2_score": 0.0,
            "predictions": [],
            "targets": [],
            "grade_accuracy": 0.0,
            "expert_system_consistency": 0.0,
        }

    # Calculate metrics
    mse = mean_squared_error(targets, predictions)
    mae = np.mean(np.abs(np.array(targets) - np.array(predictions)))

    # Calculate denominator for R² score
    targets_array = np.array(targets)
    denominator = np.sum((targets_array - np.mean(targets_array)) ** 2)

    # Calculate denominator for R² score
    targets_array = np.array(targets)
    denominator = np.sum((targets_array - np.mean(targets_array)) ** 2)

    # Calculate R² score with division by zero protection
    if denominator == 0:
        # If all target values are identical, R² is undefined
        # Common conventions: set to 0 or NaN
        r2_score = 0  # or np.nan
    else:
        numerator = np.sum((targets_array - np.array(predictions)) ** 2)
        r2_score = 1 - (numerator / denominator)

    results = {
        "mse": mse,
        "mae": mae,
        "rmse": np.sqrt(mse),  # Root Mean Square Error
        "r2_score": r2_score,
        "predictions": predictions,
        "targets": targets,
    }

    if grade_encoder is not None:
        results["grade_accuracy"] = 0.0

    if grade_predictions and grade_targets:
        accuracy = accuracy_score(grade_targets, grade_predictions)
        results["grade_accuracy"] = accuracy
        results["grade_predictions"] = grade_predictions
        results["grade_targets"] = grade_targets

        # Calculate how well we approximate the Expert System's decision boundaries
        score_ranges = {
            "Excellent": (90, 100),
            "Good": (80, 89),
            "Fair": (60, 79),
            "Poor": (40, 59),
            "Critical Risk": (0, 39),
        }

        # Measure consistency between predicted scores and grades
        consistent_predictions = 0
        total_predictions = len(predictions)

        for i, (pred_score, target_grade_idx) in enumerate(
            zip(predictions, grade_targets)
        ):
            if hasattr(model_data.get("dataset"), "grade_encoder"):
                target_grade = model_data["dataset"].grade_encoder.inverse_transform(
                    [target_grade_idx]
                )[0]
                # Map each grade to its score range and check if prediction falls within it
                # This assumes consistent grading in our system
                for grade_name, (min_val, max_val) in score_ranges.items():
                    # Simple matching for now - could be enhanced with fuzzy matching
                    if grade_name.startswith(target_grade) or target_grade.startswith(
                        grade_name
                    ):
                        if min_val <= pred_score[0] <= max_val:
                            consistent_predictions += 1
                        break

        results["expert_system_consistency"] = (
            consistent_predictions / total_predictions if total_predictions > 0 else 0.0
        )
    else:
        # Set default expert_system_consistency when no grade predictions are available
        results["expert_system_consistency"] = 0.0

    return results


def save_model(model, path: str):
    """Save a trained model to disk."""
    joblib.dump(model, path)


def load_model(path: str):
    """Load a persisted model from disk."""
    return joblib.load(path)


def main():  # pragma: no cover
    """Command-line entry point for model training."""
    parser = argparse.ArgumentParser(description="Model Trainer")
    parser.add_argument(
        "--csv_file", type=str, default="data.csv", help="Path to the CSV data file"
    )
    parser.add_argument(
        "--feature_cols",
        type=str,
        nargs="+",
        help="List of feature column names (space-separated)",
    )
    parser.add_argument(
        "--target_col",
        type=str,
        default="target_score",
        help="Name of the target column",
    )
    parser.add_argument(
        "--model_path",
        type=str,
        default="linear_model.joblib",
        help="Path to save the trained model",
    )
    parser.add_argument(
        "--input_size",
        type=int,
        default=-1,
        help="Number of input features (auto-detected if -1)",
    )
    parser.add_argument(
        "--hidden_size", type=int, default=64, help="Number of neurons in hidden layer"
    )
    parser.add_argument(
        "--output_size",
        type=int,
        default=1,
        help="Number of output units (e.g., 1 for regression or binary classification)",
    )
    parser.add_argument("--lr", type=float, default=0.001, help="Learning rate")
    parser.add_argument(
        "--epochs", type=int, default=10, help="Number of training epochs"
    )
    parser.add_argument(
        "--batch_size", type=int, default=32, help="Batch size for training and testing"
    )
    parser.add_argument(
        "--test_split",
        type=float,
        default=0.2,
        help="Proportion of dataset to use for testing",
    )
    parser.add_argument(
        "--seed", type=int, default=42, help="Random seed for reproducibility"
    )
    parser.add_argument(
        "--no_cuda", action="store_true", default=False, help="Disables CUDA training"
    )

    args = parser.parse_args()

    # Set random seed
    torch.manual_seed(args.seed)
    use_cuda = not args.no_cuda and torch.cuda.is_available()
    device = torch.device("cuda" if use_cuda else "cpu")

    print(f"Using device: {device}")
    print(f"Loading data from: {args.csv_file}")

    try:
        full_dataset = SecurityDataset(csv_file=args.csv_file)
    except Exception:
        print(f"Failed to load dataset from {args.csv_file}. Exiting.")
        return

    if args.input_size == -1:
        # Auto-detect input_size from dataset
        if len(full_dataset) > 0:
            args.input_size = full_dataset.features.shape[1]
            print(f"Auto-detected input_size: {args.input_size}")
        else:
            print(
                "Cannot auto-detect input_size from empty dataset. Please specify --input_size."
            )
            return

    # Ensure dataset is not empty for splitting
    if len(full_dataset) == 0:
        print("Dataset is empty. Cannot proceed with training and testing.")
        return

    # Split dataset
    train_size = int((1 - args.test_split) * len(full_dataset))
    test_size = len(full_dataset) - train_size

    # Handle cases where dataset is too small for the split
    if train_size <= 0 or test_size <= 0:
        print(
            f"Dataset is too small to be split with test_split={args.test_split}. Need at least {1/args.test_split if args.test_split > 0 else 'N/A'} samples for a valid split."
        )
        if len(full_dataset) > 0 and train_size <= 0:  # if all data goes to test
            print("Consider using all data for training or adjusting test_split.")
            # Or, assign all to training if test_split makes test_size zero and train_size positive
            train_dataset = full_dataset
            train_loader = DataLoader(
                train_dataset, batch_size=args.batch_size, shuffle=True
            )
            test_loader = None  # No test set
            print(
                "Using entire dataset for training as test split resulted in zero test samples."
            )
        elif len(full_dataset) > 0 and test_size <= 0:  # if all data goes to train
            train_dataset = full_dataset
            train_loader = DataLoader(
                train_dataset, batch_size=args.batch_size, shuffle=True
            )
            test_loader = None  # No test set
            print(
                "Using entire dataset for training as test split resulted in zero test samples."
            )
        else:  # Dataset is genuinely empty or cannot be split meaningfully
            return

    else:
        train_dataset, test_dataset = torch.utils.data.random_split(
            full_dataset,
            [train_size, test_size],
            generator=torch.Generator().manual_seed(args.seed),
        )
        train_loader = DataLoader(
            train_dataset, batch_size=args.batch_size, shuffle=True
        )
        test_loader = DataLoader(
            test_dataset, batch_size=args.batch_size, shuffle=False
        )

    print(
        f"Hyperparameters: LR={args.lr}, Epochs={args.epochs}, BatchSize={args.batch_size}"
    )
    print(
        f"Model: Input={args.input_size}, Hidden={args.hidden_size}, Output={args.output_size}"
    )

    model = SimpleNN(args.input_size, args.hidden_size, args.output_size).to(device)

    # Assuming regression for now. This could be a parameter too.
    # For binary classification, nn.BCELoss() with a Sigmoid in the model's output.
    # For multi-class classification, nn.CrossEntropyLoss() with LogSoftmax or Softmax in model.
    criterion = nn.MSELoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=args.lr)

    print("Starting training...")
    train_model(model, train_loader, criterion, optimizer, args.epochs, device)

    if test_loader:
        print("Starting evaluation...")
        evaluate_model(model, test_loader, criterion, device)
    else:
        print("No test data to evaluate.")

    print("Script execution finished.")


if __name__ == "__main__":  # pragma: no cover
    main()
