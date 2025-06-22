"""
Federated Learning Convergence Experiment

This experiment demonstrates basic federated learning convergence with
different numbers of clients and communication rounds.
"""

import sys
import pandas as pd
from pathlib import Path
import numpy as np
from typing import Dict, List, Any

# Add backend directory to path
backend_dir = Path(__file__).parent.parent.parent
sys.path.append(str(backend_dir))

try:
    from fl.src.fl_trainer import (
        generate_fl_datasets,
        federated_training,
        create_federated_experiment_config,
        save_federated_results,
    )
    from fl.experiments.fl_plotting import (
        plot_fl_convergence,
        plot_client_diversity,
        create_fl_summary_report,
        save_experiment_data,
    )
except ImportError as e:
    print(f"Import error: {e}")
    print("Make sure all required packages are installed and paths are correct.")
    sys.exit(1)


def analyze_client_data(dataset_paths: List[Dict[str, Path]]) -> List[Dict[str, Any]]:
    """Analyze client datasets to extract statistics for diversity plots."""

    client_stats = []

    for i, paths in enumerate(dataset_paths):
        try:
            # Load training data for this client
            df = pd.read_csv(paths["train"])

            # Basic statistics
            stats = {"client_id": i + 1, "data_size": len(df)}

            # Target statistics
            if "target_score" in df.columns:
                stats["target_mean"] = df["target_score"].mean()
                stats["target_std"] = df["target_score"].std()

            # Grade distribution
            if "target_grade" in df.columns:
                grade_counts = df["target_grade"].value_counts().to_dict()
                stats["grade_distribution"] = grade_counts

            # Feature statistics (numerical features only)
            numeric_cols = df.select_dtypes(include=[np.number]).columns
            feature_means = {}
            for col in numeric_cols:
                if not col.startswith("target_"):
                    feature_means[col] = df[col].mean()
            stats["feature_means"] = feature_means

            client_stats.append(stats)

        except Exception as e:
            print(f"Warning: Could not analyze client {i+1} data: {e}")
            # Add minimal stats
            client_stats.append(
                {"client_id": i + 1, "data_size": 0, "target_mean": 0, "target_std": 0}
            )

    return client_stats


def run_convergence_experiment():
    """Run the main convergence experiment."""
    print("Starting Federated Learning Convergence Experiment")
    print("=" * 60)

    # Experiment configuration
    config = create_federated_experiment_config(
        num_clients=4,
        samples_per_client=200,
        rounds=15,
        local_epochs=5,
        aggregation="average",
        hidden_size=64,
        hidden_layers=2,
        batch_size=16,
    )

    print(f"Configuration: {config}")
    print()

    # Generate federated datasets
    print("Generating federated datasets...")
    datasets = generate_fl_datasets(
        num_clients=config["num_clients"],
        samples_per_client=config["samples_per_client"],
        excellent_base=config["excellent_base"],
        excellent_step=config["excellent_step"],
    )

    print(f"Generated datasets for {len(datasets)} clients")
    for i, paths in enumerate(datasets):
        print(f"  Client {i+1}: Train={paths['train']}, Test={paths['test']}")

    # Analyze client diversity
    print("\nAnalyzing client data diversity...")
    client_stats = analyze_client_data(datasets)

    # Run federated training
    print(f"\nStarting federated training for {config['rounds']} rounds...")
    training_results = federated_training(
        dataset_paths=datasets,
        rounds=config["rounds"],
        local_epochs=config["local_epochs"],
        aggregation=config["aggregation"],
        hidden_size=config["hidden_size"],
        hidden_layers=config["hidden_layers"],
        batch_size=config["batch_size"],
    )

    # Prepare experiment results
    experiment_results = {
        "config": config,
        "history": training_results["history"],
        "final_metrics": training_results["final_metrics"],
        "client_stats": client_stats,
    }

    # Save results and create plots
    output_dir = Path(__file__).parent / "results" / "convergence_experiment"
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"\nSaving results to {output_dir}")
    save_experiment_data(experiment_results, output_dir)

    print("\nGenerating plots...")

    # Individual plots
    plot_fl_convergence(
        training_results["history"],
        save_path=output_dir / "convergence_plot.png",
        title="FL Convergence: 4 Clients, 15 Rounds",
    )

    plot_client_diversity(client_stats, save_path=output_dir / "client_diversity.png")

    # Summary report
    create_fl_summary_report(experiment_results, output_dir)

    print("\nExperiment completed successfully!")
    print(f"Results saved to: {output_dir}")

    # Print final metrics
    final_metrics = training_results["final_metrics"]
    print("\nFinal Performance Metrics:")
    print(f"  Global MSE: {final_metrics.get('avg_mse', 'N/A'):.4f}")
    print(f"  Global MAE: {final_metrics.get('avg_mae', 'N/A'):.4f}")
    print(f"  Global R²:  {final_metrics.get('avg_r2', 'N/A'):.4f}")

    return experiment_results


def run_client_scaling_experiment():
    """Run experiment with different numbers of clients."""
    print("\nStarting Client Scaling Experiment")
    print("=" * 50)

    client_counts = [2, 4, 6, 8]
    results = {}

    for num_clients in client_counts:
        print(f"\nTesting with {num_clients} clients...")

        config = create_federated_experiment_config(
            num_clients=num_clients,
            samples_per_client=150,
            rounds=10,
            local_epochs=3,
            hidden_size=64,
            hidden_layers=2,
        )  # Generate datasets
        datasets = generate_fl_datasets(
            num_clients=config["num_clients"],
            samples_per_client=config["samples_per_client"],
        )

        # Run training
        training_results = federated_training(
            dataset_paths=datasets,
            rounds=config["rounds"],
            local_epochs=config["local_epochs"],
            hidden_size=config["hidden_size"],
            hidden_layers=config["hidden_layers"],
        )

        results[f"{num_clients}_clients"] = training_results["history"]

        print(
            f"Final MSE with {num_clients} clients: {training_results['final_metrics']['avg_mse']:.4f}"
        )

    # Plot comparison
    from fl.experiments.fl_plotting import plot_aggregation_comparison

    output_dir = Path(__file__).parent / "results" / "client_scaling"
    output_dir.mkdir(parents=True, exist_ok=True)

    plot_aggregation_comparison(
        results, save_path=output_dir / "client_scaling_comparison.png"
    )

    print(f"Client scaling results saved to: {output_dir}")
    return results


if __name__ == "__main__":
    print("Federated Learning Experiments")
    print("==============================")

    # Run main convergence experiment
    convergence_results = run_convergence_experiment()

    # Run client scaling experiment
    scaling_results = run_client_scaling_experiment()

    print("\nAll experiments completed!")
    print("\nGenerated plots:")
    print("  - convergence_plot.png: Main FL training convergence")
    print("  - client_diversity.png: Data distribution across clients")
    print("  - client_scaling_comparison.png: Performance vs number of clients")
    print("  - fl_convergence.png: Comprehensive convergence analysis")
    print("  - fl_communication_analysis.png: Communication efficiency")
