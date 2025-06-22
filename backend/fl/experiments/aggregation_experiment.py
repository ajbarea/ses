"""
Federated Learning Aggregation Methods Comparison

This experiment compares different aggregation strategies:
- FedAvg (Simple Average)
- Weighted Average (by dataset size)
- Median Aggregation (robust to outliers)
- Secure Average (with optional differential privacy)
"""

import sys
import json
from pathlib import Path
import numpy as np
from typing import Dict, List

# Add backend directory to path
backend_dir = Path(__file__).parent.parent.parent
sys.path.append(str(backend_dir))

try:
    from fl.src.fl_trainer import (
        generate_fl_datasets,
        federated_training,
        create_federated_experiment_config,
    )
    from fl.experiments.fl_plotting import (
        plot_aggregation_comparison,
        save_experiment_data,
    )
except ImportError as e:
    print(f"Import error: {e}")
    sys.exit(1)


def run_aggregation_comparison():
    """Compare different aggregation methods."""
    print("Federated Learning Aggregation Methods Comparison")
    print("=" * 55)

    # Base configuration
    base_config = create_federated_experiment_config(
        num_clients=5,
        samples_per_client=180,
        rounds=12,
        local_epochs=4,
        hidden_size=64,
        hidden_layers=2,
    )

    # Generate common dataset for fair comparison
    print("Generating federated datasets...")
    datasets = generate_fl_datasets(
        num_clients=base_config["num_clients"],
        samples_per_client=base_config["samples_per_client"],
        excellent_base=0.2,
        excellent_step=0.15,  # More diversity between clients
    )

    aggregation_methods = ["average", "weighted", "median", "secure"]
    results = {}

    for method in aggregation_methods:
        print(f"\nTesting {method.upper()} aggregation...")

        # Use differential privacy for secure method
        use_dp = method == "secure"

        training_results = federated_training(
            dataset_paths=datasets,
            rounds=base_config["rounds"],
            local_epochs=base_config["local_epochs"],
            aggregation=method,
            hidden_size=base_config["hidden_size"],
            hidden_layers=base_config["hidden_layers"],
            batch_size=base_config["batch_size"],
            use_differential_privacy=use_dp,
            noise_scale=0.001 if use_dp else 0.0,
        )

        results[method.title()] = training_results["history"]

        final_mse = training_results["final_metrics"]["avg_mse"]
        print(f"{method.title()} - Final MSE: {final_mse:.4f}")    # Create comparison plots
    output_dir = Path(__file__).parent / "results" / "aggregation_comparison"
    output_dir.mkdir(parents=True, exist_ok=True)

    print("\nGenerating comparison plots...")
    plot_aggregation_comparison(
        results, save_path=output_dir / "aggregation_methods_comparison.png"
    )  # Save detailed results

    def convert_numpy_to_json(obj):
        """Convert numpy objects to JSON-serializable types."""
        if isinstance(obj, np.ndarray):
            return obj.tolist()
        elif isinstance(obj, (np.float32, np.float64)):
            return float(obj)
        elif isinstance(obj, (np.int32, np.int64)):
            return int(obj)
        elif isinstance(obj, dict):
            return {k: convert_numpy_to_json(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [convert_numpy_to_json(item) for item in obj]
        else:
            return obj

    with open(output_dir / "aggregation_results.json", "w") as f:
        json_results = convert_numpy_to_json(results)
        json.dump(json_results, f, indent=2)

    print(f"Results saved to: {output_dir}")
    return results


def create_performance_summary(results: Dict[str, Dict[str, List]]):
    """Create a performance summary table."""
    print("\nPerformance Summary")
    print("-" * 40)
    print(f"{'Method':<12} {'Final MSE':<12} {'Final MAE':<12} {'Best Round':<12}")
    print("-" * 40)

    for method, history in results.items():
        final_mse = history["global_mse"][-1] if "global_mse" in history else 0
        final_mae = history["global_mae"][-1] if "global_mae" in history else 0

        # Find best round (lowest MSE)
        if "global_mse" in history:
            best_round = np.argmin(history["global_mse"]) + 1
        else:
            best_round = len(history.get("rounds", []))

        print(f"{method:<12} {final_mse:<12.4f} {final_mae:<12.4f} {best_round:<12}")


def run_heterogeneity_experiment():
    """Test performance with varying data heterogeneity."""
    print("\n\nData Heterogeneity Impact Experiment")
    print("=" * 40)

    heterogeneity_levels = [
        ("Low", 0.3, 0.05),  # Similar data across clients
        ("Medium", 0.2, 0.1),  # Moderate differences
        ("High", 0.1, 0.2),  # Very different data distributions
    ]

    results = {}

    for level_name, excellent_base, excellent_step in heterogeneity_levels:
        print(f"\nTesting {level_name} heterogeneity...")

        # Generate datasets with different heterogeneity
        datasets = generate_fl_datasets(
            num_clients=4,
            samples_per_client=200,
            excellent_base=excellent_base,
            excellent_step=excellent_step,
        )

        training_results = federated_training(
            dataset_paths=datasets,
            rounds=10,
            local_epochs=4,
            aggregation="average",
            hidden_size=64,
            hidden_layers=2,
        )

        results[f"{level_name} Heterogeneity"] = training_results["history"]
        final_mse = training_results["final_metrics"]["avg_mse"]
        print(f"{level_name} heterogeneity - Final MSE: {final_mse:.4f}")

    # Plot heterogeneity comparison
    output_dir = Path(__file__).parent / "results" / "heterogeneity_experiment"
    output_dir.mkdir(parents=True, exist_ok=True)

    plot_aggregation_comparison(
        results, save_path=output_dir / "heterogeneity_impact.png"
    )

    print(f"Heterogeneity experiment results saved to: {output_dir}")
    return results


if __name__ == "__main__":
    print("Running Federated Learning Aggregation Experiments")
    print("=" * 55)

    # Main aggregation comparison
    aggregation_results = run_aggregation_comparison()
    create_performance_summary(aggregation_results)

    # Data heterogeneity experiment
    heterogeneity_results = run_heterogeneity_experiment()

    print("\n" + "=" * 55)
    print("All aggregation experiments completed!")
    print("\nGenerated plots:")
    print(
        "  - aggregation_methods_comparison.png: Compare FedAvg, Weighted, Median, Secure"
    )
    print("  - heterogeneity_impact.png: Impact of data distribution differences")
    print("\nKey findings will help you understand:")
    print("  - Which aggregation method works best for your data")
    print("  - How data heterogeneity affects convergence")
    print("  - Trade-offs between privacy and performance")
