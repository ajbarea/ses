"""
Simplified ML trainer using only scikit-learn (compatible with current environment).
This is a fallback implementation when PyTorch is not available.
"""

import pandas as pd
import numpy as np
from sklearn.linear_model import LinearRegression
from sklearn.ensemble import RandomForestRegressor
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import mean_squared_error, mean_absolute_error, r2_score
import joblib


def train_model(train_csv, target_col="target_score", **kwargs):
    """Train a scikit-learn model on the data."""
    print(f"Loading training data from {train_csv}...")

    # Load data
    df = pd.read_csv(train_csv)

    # Separate features and target
    feature_cols = [col for col in df.columns if not col.startswith("target_")]
    x_df = df[feature_cols].copy()
    y = df[target_col].values

    # Handle categorical variables
    categorical_cols = x_df.select_dtypes(include=["object"]).columns

    # Encode categorical variables
    encoders = {}
    for col in categorical_cols:
        le = LabelEncoder()
        x_df[col] = le.fit_transform(x_df[col].astype(str))
        encoders[col] = le

    # Scale features
    scaler = StandardScaler()
    x_scaled = scaler.fit_transform(
        x_df.values
    )  # Train model - using RandomForest for better performance than LinearRegression
    print("Training Random Forest model...")
    model = RandomForestRegressor(
        n_estimators=100, random_state=42, min_samples_leaf=2, max_features="sqrt"
    )
    model.fit(x_scaled, y)

    # Calculate training error
    train_pred = model.predict(x_scaled)
    train_mse = mean_squared_error(y, train_pred)

    print(f"Training MSE: {train_mse:.4f}")

    return {
        "model": model,
        "encoders": encoders,
        "scaler": scaler,
        "feature_cols": feature_cols,
        "val_mse": train_mse,
    }


def evaluate_security_model(model_data, test_csv, target_col="target_score"):
    """Evaluate the trained model on test data."""
    print(f"Loading test data from {test_csv}...")

    # Load test data
    df = pd.read_csv(test_csv)

    # Extract model components
    model = model_data["model"]
    encoders = model_data["encoders"]
    scaler = model_data["scaler"]
    feature_cols = model_data["feature_cols"]

    # Prepare test features
    X_test_df = df[feature_cols].copy()
    y_test = df[target_col].values

    # Handle categorical variables
    categorical_cols = X_test_df.select_dtypes(include=["object"]).columns
    for col in categorical_cols:
        if col in encoders:
            # Handle unseen categories by assigning them to the most frequent class
            le = encoders[col]
            X_test_df[col] = X_test_df[col].astype(str)

            # Replace unseen categories with the most frequent one from training
            unseen_mask = ~X_test_df[col].isin(le.classes_)
            if unseen_mask.any():
                most_frequent = le.classes_[0]  # Use first class as default
                X_test_df.loc[unseen_mask, col] = most_frequent

            X_test_df[col] = le.transform(X_test_df[col])

    # Scale features
    X_test_scaled = scaler.transform(X_test_df.values)

    # Make predictions
    predictions = model.predict(X_test_scaled)

    # Calculate metrics
    mse = mean_squared_error(y_test, predictions)
    mae = mean_absolute_error(y_test, predictions)
    rmse = np.sqrt(mse)
    r2 = r2_score(y_test, predictions)

    # Convert to format expected by the main script
    predictions_formatted = [[pred] for pred in predictions]
    targets_formatted = [[target] for target in y_test]

    # Calculate grade accuracy if target_grade exists
    grade_accuracy = None
    if "target_grade" in df.columns:
        # Simple grade classification based on score thresholds
        def score_to_grade(score):
            if score >= 80:
                return "Excellent"
            elif score >= 60:
                return "Good"
            elif score >= 40:
                return "Fair"
            else:
                return "Critical Risk"

        predicted_grades = [score_to_grade(pred) for pred in predictions]
        actual_grades = df["target_grade"].values
        grade_accuracy = np.mean(
            [pg == ag for pg, ag in zip(predicted_grades, actual_grades)]
        )

    results = {
        "mse": mse,
        "mae": mae,
        "rmse": rmse,
        "r2_score": r2,
        "predictions": predictions_formatted,
        "targets": targets_formatted,
    }

    if grade_accuracy is not None:
        results["grade_accuracy"] = grade_accuracy

    return results


def save_model(model_data, path):
    """Save the trained model and preprocessing components."""
    joblib.dump(model_data, path)


def load_model(path):
    """Load a saved model."""
    return joblib.load(path)
