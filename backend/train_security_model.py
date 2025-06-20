#!/usr/bin/env python3
"""
Train and evaluate a machine learning model to approximate the Expert System.
"""

# Try to use the full PyTorch version, fallback to simple sklearn version
try:
    from src.ml_trainer import train_model, evaluate_security_model

    print("Using PyTorch-based ML trainer")
except ImportError:
    from src.ml_trainer_simple import train_model, evaluate_security_model

    print("Using simplified scikit-learn ML trainer (PyTorch not available)")


def main():
    # Training parameters
    train_csv = "security_data_split_train.csv"
    test_csv = "security_data_split_test.csv"

    print("Training Security Prediction Model...")
    print("=" * 50)

    # Train the model
    model_data = train_model(
        train_csv,
        model_type="security",
        target_col="target_score",
        epochs=100,
        hidden_size=128,
        hidden_layers=3,
        lr=0.001,
        batch_size=16,
        no_cuda=False,
    )

    print(f"Training completed. Final validation MSE: {model_data['val_mse']:.4f}")

    # Evaluate on test set
    print("\nEvaluating on test set...")
    test_results = evaluate_security_model(model_data, test_csv)

    print(f"Test MSE: {test_results['mse']:.4f}")
    print(f"Test MAE: {test_results['mae']:.4f}")
    print(f"Test RMSE: {test_results.get('rmse', 'N/A'):.4f}")
    print(f"R² Score: {test_results.get('r2_score', 'N/A'):.4f}")

    if "grade_accuracy" in test_results:
        print(f"Grade Classification Accuracy: {test_results['grade_accuracy']:.4f}")

    if "expert_system_consistency" in test_results:
        print(
            f"Expert System Consistency: {test_results['expert_system_consistency']:.4f}"
        )
        print(
            "(How often predicted scores align with Expert System grade boundaries)"
        )  # Show some example predictions
    print("\nSample Predictions vs Actual:")
    print("-" * 60)
    print("Sample | Predicted | Actual | Error | Expert System Approximation")
    print("-" * 60)
    predictions = test_results["predictions"][:10]
    targets = test_results["targets"][:10]

    for i, (pred, actual) in enumerate(zip(predictions, targets)):
        error = abs(pred - actual)
        # Determine approximation quality
        if error < 5:
            quality = "Excellent"
        elif error < 10:
            quality = "Good"
        elif error < 20:
            quality = "Fair"
        else:
            quality = "Poor"

        print(
            f"  {i+1:2d}   |   {pred:5.1f}   |  {actual:5.1f}  | {error:5.1f} | {quality}"
        )

    # Overall approximation assessment
    print(f"\n{'='*50}")
    print("EXPERT SYSTEM APPROXIMATION QUALITY ASSESSMENT")
    print(f"{'='*50}")

    avg_error = test_results["mae"]
    if avg_error < 5:
        print("🟢 EXCELLENT: Your ML model closely approximates the Expert System")
    elif avg_error < 10:
        print("🟡 GOOD: Your ML model reasonably approximates the Expert System")
    elif avg_error < 20:
        print("🟠 FAIR: Your ML model partially approximates the Expert System")
    else:
        print(
            "🔴 POOR: Your ML model needs improvement to approximate the Expert System"
        )

    print(f"Average prediction error: {avg_error:.2f} points")
    if test_results.get("r2_score"):
        print(f"R² correlation with Expert System: {test_results['r2_score']:.3f}")


if __name__ == "__main__":
    main()
