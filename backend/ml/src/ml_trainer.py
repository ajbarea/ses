"""Machine Learning Training and Evaluation Module.

This module provides neural network and linear regression models for security evaluation
tasks. It includes dataset preparation, model training, and evaluation functionality
with support for both score prediction and security grade classification.

Key Components:
    - SecurityDataset: Custom dataset for loading and preprocessing security metrics
    - SecurityNN: Neural network model for security score prediction and grade classification
    - SimpleNN: Basic feed-forward neural network for regression tasks
    - Training and evaluation utilities for both PyTorch and scikit-learn models
    - Experimentation: Use `ml_experiments.py` for neural network architecture sweeps (layers/neurons)

"""

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
    """Custom dataset for security metrics preprocessing and loading.

    Handles preprocessing of both categorical and numerical features, with support
    for both security scores and grades. Features are automatically encoded and
    scaled based on data types.

    Args:
        csv_file (str): Path to CSV file containing security metrics data.
        target_col (str, optional): Column name for target scores. Defaults to "target_score".
        fit_encoders (bool, optional): Whether to fit new encoders or use existing ones. Defaults to True.
        encoders (dict, optional): Pre-fitted LabelEncoders for categorical columns. Required if fit_encoders=False.
        scaler (StandardScaler, optional): Pre-fitted scaler for numerical columns. Required if fit_encoders=False.
        grade_encoder (LabelEncoder, optional): Pre-fitted encoder for security grades.

    Attributes:
        features (torch.Tensor): Preprocessed feature tensor.
        targets (torch.Tensor): Target scores tensor.
        target_grades (torch.Tensor): Optional encoded security grades tensor.
        encoders (dict): LabelEncoders for categorical features.
        scaler (StandardScaler): Scaler for numerical features.
        grade_encoder (LabelEncoder): Optional encoder for security grades.
    """

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

            # Encode categorical variables - vectorized approach
            df_encoded = df[feature_cols].copy()

            # Process all categorical columns efficiently
            if len(categorical_cols) > 0:
                for col in categorical_cols:
                    le = LabelEncoder()
                    df_encoded[col] = le.fit_transform(df[col].astype(str))
                    self.encoders[col] = le

            # Scale numerical features in one operation
            if len(numerical_cols) > 0:
                df_encoded[numerical_cols] = self.scaler.fit_transform(
                    df[numerical_cols]
                )

        else:
            self.encoders = encoders
            self.scaler = scaler

            # Apply existing encoders - optimized preprocessing
            df_encoded = df[feature_cols].copy()

            # Process categorical columns efficiently with batch operations
            for col in categorical_cols:
                if col in self.encoders:
                    # Handle unseen categories gracefully - optimized with dictionary mapping
                    class_mapping = {
                        cls: self.encoders[col].transform([cls])[0]
                        for cls in self.encoders[col].classes_
                    }
                    df_encoded[col] = df[col].astype(str).map(class_mapping).fillna(0)
                else:
                    df_encoded[col] = 0

            # Handle numerical columns - ensure consistency with fitted scaler
            if len(numerical_cols) > 0:
                # Get the feature names that were used during scaler fitting
                scaler_feature_names = getattr(self.scaler, "feature_names_in_", None)

                if scaler_feature_names is not None:
                    # Ensure all required columns exist in df_encoded
                    for col in scaler_feature_names:
                        if col not in df_encoded.columns:
                            df_encoded[col] = 0

                    # Transform only the columns that were used during fitting
                    df_encoded[scaler_feature_names] = self.scaler.transform(
                        df_encoded[scaler_feature_names]
                    )
                else:
                    # Fallback: transform all numerical columns
                    df_encoded[numerical_cols] = self.scaler.transform(
                        df[numerical_cols]
                    )

        # Convert to tensors efficiently - avoid unnecessary copies
        self.features = torch.from_numpy(df_encoded.values.astype(np.float32))
        self.targets = torch.from_numpy(
            df[target_col].values.astype(np.float32)
        ).unsqueeze(1)

        # Handle grade encoding if available
        self.target_grades = None
        if "target_grade" in df.columns:
            if fit_encoders:
                self.grade_encoder = LabelEncoder()
                encoded_grades = self.grade_encoder.fit_transform(df["target_grade"])
            else:
                self.grade_encoder = grade_encoder
                if self.grade_encoder:
                    # Handle unseen grades gracefully
                    try:
                        encoded_grades = self.grade_encoder.transform(
                            df["target_grade"]
                        )
                    except ValueError:
                        # Map unseen grades to first class
                        mapped_grades = []
                        for grade in df["target_grade"]:
                            if grade in self.grade_encoder.classes_:
                                mapped_grades.append(grade)
                            else:
                                mapped_grades.append(self.grade_encoder.classes_[0])
                        encoded_grades = self.grade_encoder.transform(mapped_grades)
                else:
                    encoded_grades = np.zeros(len(df))

            self.target_grades = torch.from_numpy(encoded_grades.astype(np.int64))

    def __len__(self):
        return len(self.targets)

    def __getitem__(self, idx):
        if self.target_grades is not None:
            return self.features[idx], self.targets[idx], self.target_grades[idx]
        return self.features[idx], self.targets[idx]


class SecurityNN(nn.Module):
    """Neural network for security score prediction and grade classification.

    Features a configurable architecture with multiple hidden layers, layer
    normalization, and dropout for regularization. Includes both a score predictor
    and an optional grade classifier head.

    Args:
        input_size (int): Number of input features.
        hidden_size (int, optional): Size of hidden layers. Defaults to 64.
        hidden_layers (int, optional): Number of hidden layers. Defaults to 2.
        dropout_rate (float, optional): Dropout probability. Defaults to 0.2.

    Attributes:
        score_predictor (nn.Sequential): Neural network for score prediction (0-100).
        grade_classifier (nn.Sequential): Optional network for grade classification.
    """

    def __init__(
        self,
        input_size: int,
        hidden_size: int = 64,
        hidden_layers: int = 2,
        dropout_rate: float = 0.2,
    ):
        super().__init__()

        # Build score predictor with a configurable number of hidden layers
        layers = []
        in_features = input_size
        for _ in range(max(1, hidden_layers)):
            layers.extend(
                [
                    nn.Linear(in_features, hidden_size),
                    nn.LayerNorm(hidden_size),
                    nn.ReLU(),
                    nn.Dropout(dropout_rate),
                ]
            )
            in_features = hidden_size

        layers.extend([nn.Linear(in_features, 1), nn.Sigmoid()])
        self.score_predictor = nn.Sequential(*layers)

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
    """Basic feed-forward neural network with configurable layers.

    A simple neural network implementation that supports variable depth through
    configurable hidden layers.

    Args:
        input_size (int): Number of input features.
        hidden_size (int): Number of neurons in hidden layers.
        output_size (int): Number of output neurons.
        hidden_layers (int, optional): Number of hidden layers. Defaults to 1.

    Attributes:
        net (nn.Sequential): The neural network layers.
    """

    def __init__(
        self,
        input_size: int,
        hidden_size: int,
        output_size: int,
        hidden_layers: int = 1,
    ):
        super().__init__()
        layers = []
        in_features = input_size
        for _ in range(max(1, hidden_layers)):
            layers.append(nn.Linear(in_features, hidden_size))
            layers.append(nn.ReLU())
            in_features = hidden_size
        layers.append(nn.Linear(in_features, output_size))
        self.net = nn.Sequential(*layers)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """Forward pass computation.

        Args:
            x (torch.Tensor): Input tensor of shape (batch_size, input_size)

        Returns:
            torch.Tensor: Output tensor of shape (batch_size, output_size)
        """
        return self.net(x)


class CSVDataset(Dataset):
    """Basic dataset for loading CSV data into PyTorch tensors.

    A simplified dataset class that loads features and a single target column
    from a CSV file, converting them directly to PyTorch tensors without any
    preprocessing.

    Args:
        csv_file (str): Path to the CSV file containing the data.
        target_col (str, optional): Name of the target column. Defaults to "target_score".

    Attributes:
        features (torch.Tensor): Feature tensor of shape (n_samples, n_features).
        targets (torch.Tensor): Target tensor of shape (n_samples, 1).
    """

    def __init__(self, csv_file: str, target_col: str = "target_score"):
        df = pd.read_csv(csv_file)
        self.features = torch.tensor(
            df.drop(columns=[target_col]).to_numpy(), dtype=torch.float32
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
    progress_bar=False,
) -> list:
    """Train a SecurityNN model with support for both score and grade prediction.

    Args:
        model (nn.Module): SecurityNN model instance.
        loader (DataLoader): DataLoader for training data.
        criterion: Loss function for score prediction.
        optimizer: Optimizer instance.
        epochs (int): Number of training epochs.
        device (torch.device): Device to train on (cuda/cpu).
        classification_loss: Optional loss function for grade classification.
        progress_bar (bool, optional): Whether to show a progress bar for epochs. Defaults to False.

    Returns:
        list: Training losses for each epoch.

    Note:
        If the dataset includes grade labels, both score prediction and grade
        classification losses are combined with a 0.7/0.3 weighting.
    """
    model.to(device)
    losses = []

    epoch_iter = range(epochs)
    if progress_bar:
        try:
            from tqdm import tqdm

            epoch_iter = tqdm(epoch_iter, desc="Epochs", leave=False)
        except ImportError:
            pass

    for _ in epoch_iter:
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

    return losses


def _train_torch_model(
    model: nn.Module,
    loader: torch.utils.data.DataLoader,
    criterion,
    optimizer,
    epochs: int,
    device: torch.device,
    progress_bar=False,
) -> list:
    """Train a generic PyTorch model.

    A basic training loop for PyTorch models that performs forward passes,
    backpropagation, and optimization steps.

    Args:
        model (nn.Module): The PyTorch model to train.
        loader (DataLoader): DataLoader providing training batches.
        criterion: Loss function for computing training error.
        optimizer: Optimizer for updating model parameters.
        epochs (int): Number of complete passes through the training data.
        device (torch.device): Device (CPU/GPU) to use for training.
        progress_bar (bool, optional): Whether to show a progress bar for epochs. Defaults to False.

    Returns:
        list: Training loss values for each epoch.
    """
    model.to(device)
    losses = []
    epoch_iter = range(epochs)
    if progress_bar:
        try:
            from tqdm import tqdm

            epoch_iter = tqdm(epoch_iter, desc="Epochs", leave=False)
        except ImportError:
            pass
    for _ in epoch_iter:
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
    """Train a scikit-learn linear regression model with preprocessing.

    Handles categorical and numerical feature preprocessing automatically, including
    label encoding for categorical variables and standard scaling for numerical features.

    Args:
        csv_file (str): Path to CSV file containing training data.
        target_col (str, optional): Name of target column. Defaults to "target_score".

    Returns:
        tuple: A tuple containing:
            - tuple: (model, encoders, scaler, feature_cols) for future preprocessing
            - float: Mean squared error on training data
    """
    df = pd.read_csv(csv_file)

    # Extract non-target columns as features
    feature_cols = [col for col in df.columns if not col.startswith("target_")]

    # Split features into categorical and numerical based on dtype
    categorical_cols = df[feature_cols].select_dtypes(include=["object"]).columns
    numerical_cols = df[feature_cols].select_dtypes(include=["number"]).columns

    # Preprocess categorical features using label encoding
    encoders = {}
    df_encoded = df[feature_cols].copy()
    for col in categorical_cols:
        le = LabelEncoder()
        df_encoded[col] = le.fit_transform(df[col].astype(str))
        encoders[col] = le

    # Scale numerical features to zero mean and unit variance
    scaler = StandardScaler()
    if len(numerical_cols) > 0:
        df_encoded[numerical_cols] = scaler.fit_transform(df[numerical_cols])

    # Prepare final arrays and train model
    X = df_encoded.values
    y = df[target_col].values

    model = LinearRegression().fit(X, y)
    preds = model.predict(X)

    return (model, encoders, scaler, feature_cols), mean_squared_error(y, preds)


def _load_xy(csv_file: str, target_col: str = "target_score"):
    """Load X and y from a CSV, removing the target column and ignoring 'target_grade'."""
    df = pd.read_csv(csv_file)
    y = df[target_col]

    feature_cols = [col for col in df.columns if not col.startswith("target_")]

    # Handle categorical variables
    categorical_cols = df[feature_cols].select_dtypes(include=["object"]).columns
    numerical_cols = df[feature_cols].select_dtypes(include=["number"]).columns

    # Encode categorical variables
    encoders = {}
    df_encoded = df[feature_cols].copy()
    for col in categorical_cols:
        le = LabelEncoder()
        df_encoded[col] = le.fit_transform(df[col].astype(str))
        encoders[col] = le

    # Scale numerical features
    scaler = StandardScaler()
    if len(numerical_cols) > 0:
        df_encoded[numerical_cols] = scaler.fit_transform(df[numerical_cols])

    X = df_encoded
    return X, y


def train_model(*args, **kwargs):
    """Train a security evaluation model.

    Supports multiple training modes based on input arguments:
    1. PyTorch model training (6 positional args)
    2. Security model training (model_type="security")
    3. Sklearn model training (1-2 positional args)

    Args:
        *args: Variable length argument list.
        **kwargs: Arbitrary keyword arguments.
            For security model:
                - train_csv (str): Path to training data
                - target_col (str): Target column name
                - hidden_size (int): Hidden layer size
                - hidden_layers (int): Number of hidden layers
                - epochs (int): Training epochs
                - batch_size (int): Batch size
                - lr (float): Learning rate
                - no_cuda (bool): Disable CUDA

    Returns:
        Union[dict, tuple]: Training results based on mode:
            - Security model: Dict with model, dataset, metrics, and encoders
            - Sklearn model: Tuple of (model, encoders, scaler, features), mse
            - PyTorch model: List of training losses
    """

    if len(args) == 6:
        # PyTorch training: (model, loader, criterion, optimizer, epochs, device)
        model, loader, criterion, optimizer, epochs, device = args
        progress_bar = kwargs.get("progress_bar", False)
        if hasattr(model, "score_predictor"):  # SecurityNN
            classification_loss = (
                nn.CrossEntropyLoss()
                if any(len(batch) == 3 for batch in loader)
                else None
            )
            return _train_security_model(
                model,
                loader,
                criterion,
                optimizer,
                epochs,
                device,
                classification_loss,
                progress_bar=progress_bar,
            )
        else:  # Regular NN
            return _train_torch_model(
                model,
                loader,
                criterion,
                optimizer,
                epochs,
                device,
                progress_bar=progress_bar,
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
            model = SecurityNN(
                1,
                kwargs.get("hidden_size", 64),
                kwargs.get("hidden_layers", 2),
            )  # Minimal model
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

        train_loader = DataLoader(
            train_ds, batch_size=batch_size, shuffle=True, num_workers=0
        )
        val_loader = (
            DataLoader(val_ds, batch_size=batch_size, shuffle=False, num_workers=0)
            if val_size > 0
            else None
        )

        # Create model
        input_size = dataset.features.shape[1]
        model = SecurityNN(
            input_size,
            kwargs.get("hidden_size", 64),
            kwargs.get("hidden_layers", 2),
        )

        # Training setup
        device = torch.device(
            "cuda"
            if torch.cuda.is_available() and not kwargs.get("no_cuda", False)
            else "cpu"
        )
        criterion = nn.MSELoss()
        optimizer = torch.optim.Adam(
            model.parameters(),
            lr=kwargs.get("lr", 0.001),
            weight_decay=kwargs.get("weight_decay", 1e-4),
        )  # Train
        losses = train_model(
            model,
            train_loader,
            criterion,
            optimizer,
            kwargs.get("epochs", 50),
            device,
            progress_bar=True,
        )

        # Evaluate
        model.eval()
        val_predictions = []
        val_targets = []

        if val_loader:
            with torch.no_grad():
                for batch in val_loader:
                    if len(batch) == 3:
                        x, y_score, _ = batch
                    else:
                        x, y_score = batch

                    x, y_score = x.to(device), y_score.to(device)
                    pred = model(x)

                    val_predictions.extend(pred.cpu().numpy().flatten())
                    val_targets.extend(y_score.cpu().numpy().flatten())

        val_mse = (
            mean_squared_error(val_targets, val_predictions)
            if val_predictions
            else float("inf")
        )

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
    """Evaluate a trained model on test data.

    Supports both new-style models (with preprocessing information) and legacy models.
    Automatically applies the same preprocessing steps used during training.

    Args:
        model_or_tuple: Either a trained model instance or a tuple containing:
            ((model, encoders, scaler, feature_cols), mse)
        test_csv (str): Path to CSV file containing test data.
        target_col (str, optional): Name of target column. Defaults to "target_score".

    Returns:
        float: Mean squared error on test data.

    Note:
        For legacy models without preprocessing information, basic label encoding
        and scaling will be applied to the test data.
    """
    if isinstance(model_or_tuple, tuple) and len(model_or_tuple) == 2:
        # New format: ((model, encoders, scaler, feature_cols), mse)
        model_data, _ = model_or_tuple
        if isinstance(model_data, tuple) and len(model_data) == 4:
            model, encoders, scaler, feature_cols = model_data

            # Load test data and apply same preprocessing
            df = pd.read_csv(test_csv)
            y_test = df[target_col].values

            # Apply same preprocessing as training
            categorical_cols = (
                df[feature_cols].select_dtypes(include=["object"]).columns
            )
            numerical_cols = df[feature_cols].select_dtypes(include=["number"]).columns

            df_encoded = df[feature_cols].copy()

            # Apply encoders to categorical columns
            for col in categorical_cols:
                if col in encoders:
                    # Handle unseen categories gracefully - optimized with dictionary mapping
                    df_encoded[col] = (
                        df[col]
                        .astype(str)
                        .map(
                            {
                                cls: encoders[col].transform([cls])[0]
                                for cls in encoders[col].classes_
                            }
                        )
                        .fillna(0)
                    )
                else:
                    df_encoded[col] = 0

            # Apply scaler to numerical columns
            if len(numerical_cols) > 0:
                df_encoded[numerical_cols] = scaler.transform(df[numerical_cols])

            x_test = df_encoded.values
            preds = model.predict(x_test)
            return mean_squared_error(y_test, preds)
        else:
            # Old format: just (model, mse)
            model = model_or_tuple[0]
    else:
        model = model_or_tuple

    # Fallback to old behavior for backward compatibility
    x_test, y_test = _load_xy(test_csv, target_col)
    preds = model.predict(x_test)
    return mean_squared_error(y_test, preds)


def evaluate_security_model(
    model_data, test_csv: str, target_col: str = "target_score"
):
    """Evaluate a SecurityNN model on test data.

    Args:
        model_data (dict): Dictionary containing model and preprocessing objects.
        test_csv (str): Path to test CSV file.
        target_col (str, optional): Target score column name. Defaults to "target_score".

    Returns:
        dict: Evaluation metrics including MSE, MAE, RMSE, and consistency metrics.
    """
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

    test_loader = DataLoader(test_dataset, batch_size=32, shuffle=False, num_workers=0)
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

            # Handle both single-task and multi-task prediction
            if len(batch) == 3 and grade_encoder:
                score_pred, grade_pred = model(x, predict_grade=True)
                grade_predictions.extend(torch.argmax(grade_pred, dim=1).cpu().numpy())
            else:
                score_pred = model(x)

            predictions.extend(score_pred.cpu().numpy().flatten())
            targets.extend(y_score.cpu().numpy().flatten())

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

    # Calculate metrics using numpy arrays (avoid duplicate array creation)
    targets_array = np.array(targets)
    predictions_array = np.array(predictions)
    mae = np.mean(np.abs(predictions_array - targets_array))

    # Calculate denominator for R² score
    targets_mean = np.mean(targets_array)
    denominator = np.sum((targets_array - targets_mean) ** 2)

    # Calculate R² score with division by zero protection
    if denominator == 0:
        # If all target values are identical, R² is undefined
        # Common conventions: set to 0 or NaN
        r2_score = 0  # or np.nan
    else:
        numerator = np.sum((targets_array - predictions_array) ** 2)
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
        results["grade_targets"] = (
            grade_targets  # Calculate how well we approximate the Expert System's decision boundaries
        )
        score_ranges = {
            "Excellent": (90, 100),
            "Good": (80, 89),
            "Fair": (60, 79),
            "Poor": (40, 59),
            "Critical Risk": (0, 39),
        }

        # Measure consistency between predicted scores and grades - optimized
        consistent_predictions = 0
        total_predictions = len(predictions)

        if total_predictions > 0:
            # Convert predictions to numpy array for vectorized operations
            pred_scores = np.array(predictions).flatten()

            for i, (pred_score, target_grade_idx) in enumerate(
                zip(pred_scores, grade_targets)
            ):
                if hasattr(model_data.get("dataset"), "grade_encoder"):
                    target_grade = model_data[
                        "dataset"
                    ].grade_encoder.inverse_transform([target_grade_idx])[0]
                    # Map each grade to its score range and check if prediction falls within it
                    # This assumes consistent grading in our system
                    for grade_name, (min_val, max_val) in score_ranges.items():
                        # Simple matching for now - could be enhanced with fuzzy matching
                        if grade_name.startswith(
                            target_grade
                        ) or target_grade.startswith(grade_name):
                            if min_val <= pred_score <= max_val:
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
    """Save a trained model to disk.

    Args:
        model: Trained model instance.
        path (str): Path to save the model.
    """
    joblib.dump(model, path)


def load_model(path: str):
    """Load a saved model from disk.

    Args:
        path (str): Path to the saved model file.

    Returns:
        The loaded model instance.
    """
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
        "--hidden_size",
        type=int,
        default=64,
        help="Number of neurons in each hidden layer",
    )
    parser.add_argument(
        "--hidden_layers",
        type=int,
        default=1,
        help="Number of hidden layers for the simple model",
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

    try:
        full_dataset = SecurityDataset(csv_file=args.csv_file)
    except Exception:
        print(f"Error loading dataset from {args.csv_file}. Please check the file.")
        return

    if args.input_size == -1:
        # Auto-detect input_size from dataset
        if len(full_dataset) > 0:
            args.input_size = full_dataset.features.shape[1]
        else:
            print("Dataset is empty. Cannot determine input size.")
            return

    # Ensure dataset is not empty for splitting
    if len(full_dataset) == 0:
        return

    # Split dataset
    train_size = int((1 - args.test_split) * len(full_dataset))
    test_size = len(full_dataset) - train_size

    # Handle cases where dataset is too small for the split
    if train_size <= 0 or test_size <= 0:
        if len(full_dataset) > 0:
            train_dataset = full_dataset
            train_loader = DataLoader(
                train_dataset, batch_size=args.batch_size, shuffle=True, num_workers=0
            )
            test_loader = None  # No test set
        else:  # Dataset is genuinely empty or cannot be split meaningfully
            return
    else:
        train_dataset, test_dataset = torch.utils.data.random_split(
            full_dataset,
            [train_size, test_size],
            generator=torch.Generator().manual_seed(args.seed),
        )
        train_loader = DataLoader(
            train_dataset, batch_size=args.batch_size, shuffle=True, num_workers=0
        )
        test_loader = DataLoader(
            test_dataset, batch_size=args.batch_size, shuffle=False, num_workers=0
        )

    model = SimpleNN(
        args.input_size,
        args.hidden_size,
        args.output_size,
        hidden_layers=args.hidden_layers,
    ).to(device)
    criterion = nn.MSELoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=args.lr, weight_decay=1e-4)

    train_model(model, train_loader, criterion, optimizer, args.epochs, device)

    if test_loader:
        model.eval()
        with torch.no_grad():
            for x, y in test_loader:
                x, y = x.to(device), y.to(device)
                model(x)


if __name__ == "__main__":  # pragma: no cover
    main()
