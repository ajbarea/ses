"""
Federated Learning Privacy Experiment

This experiment demonstrates the privacy-utility tradeoff in federated learning
by testing different levels of differential privacy noise.
"""

from pathlib import Path

from fl.src.fl_trainer import (
    generate_fl_datasets,
    federated_training,
    create_federated_experiment_config,
)
from fl.experiments.fl_plotting import (
    plot_privacy_impact,
    plot_aggregation_comparison,
    save_experiment_data,
)


def run_privacy_experiment():
    """Test the impact of differential privacy on model performance."""
    print("Federated Learning Privacy Impact Experiment")
    print("=" * 50)

    # Base configuration
    config = create_federated_experiment_config(
        num_clients=4,
        samples_per_client=200,
        rounds=12,
        local_epochs=4,
        hidden_size=64,
        hidden_layers=2,
    )

    # Generate federated datasets
    print("Generating federated datasets...")
    datasets = generate_fl_datasets(
        num_clients=config["num_clients"],
        samples_per_client=config["samples_per_client"],
    )

    # Test different noise scales
    noise_scales = [0.0, 0.001, 0.005, 0.01, 0.05]
    results = {}

    for noise_scale in noise_scales:
        use_privacy = noise_scale > 0

        if use_privacy:
            print(
                f"\nTesting with differential privacy (noise scale: {noise_scale})..."
            )
        else:
            print("\nTesting baseline (no privacy)...")

        training_results = federated_training(
            dataset_paths=datasets,
            rounds=config["rounds"],
            local_epochs=config["local_epochs"],
            aggregation="secure" if use_privacy else "average",
            hidden_size=config["hidden_size"],
            hidden_layers=config["hidden_layers"],
            batch_size=config["batch_size"],
            use_differential_privacy=use_privacy,
            noise_scale=noise_scale,
        )

        if noise_scale == 0.0:
            label = "No Privacy"
        else:
            label = f"DP (σ={noise_scale})"

        results[label] = training_results["history"]

        final_mse = training_results["final_metrics"]["avg_mse"]
        print(f"Final MSE: {final_mse:.4f}")

    # Calculate privacy-utility tradeoff metrics
    baseline_mse = results["No Privacy"]["global_mse"][-1]

    print("\nPrivacy-Utility Tradeoff Summary:")
    print("-" * 40)
    print(f"{'Noise Scale':<12} {'Final MSE':<12} {'Utility Loss':<12}")
    print("-" * 40)

    utility_losses = []
    for noise_scale in noise_scales:
        if noise_scale == 0.0:
            label = "No Privacy"
            utility_loss = 0.0
        else:
            label = f"DP (σ={noise_scale})"
            current_mse = results[label]["global_mse"][-1]
            utility_loss = (current_mse - baseline_mse) / baseline_mse * 100

        utility_losses.append(utility_loss)
        print(
            f"{noise_scale:<12} {results[label]['global_mse'][-1]:<12.4f} {utility_loss:<12.1f}%"
        )

    # Create plots
    output_dir = Path(__file__).parent / "results" / "privacy_experiment"
    output_dir.mkdir(parents=True, exist_ok=True)

    print("\nGenerating privacy impact plots...")

    # Privacy comparison plot
    baseline_history = results["No Privacy"]
    private_history = results["DP (σ=0.001)"]  # Use mild privacy for comparison

    plot_privacy_impact(
        baseline_history,
        private_history,
        noise_scales,
        save_path=output_dir / "privacy_impact.png",
    )

    # All methods comparison
    plot_aggregation_comparison(
        results, save_path=output_dir / "privacy_methods_comparison.png"
    )

    # Save detailed results
    experiment_results = {
        "config": config,
        "privacy_results": {
            "baseline": baseline_history,
            "private": private_history,
            "noise_scales": noise_scales,
            "utility_losses": utility_losses,
        },
        "all_results": results,
    }

    save_experiment_data(experiment_results, output_dir)

    print(f"Privacy experiment results saved to: {output_dir}")
    return results


def run_communication_efficiency_experiment():
    """Test communication efficiency with different strategies."""
    print("\n\nCommunication Efficiency Experiment")
    print("=" * 40)

    # Test different communication frequencies
    communication_strategies = [
        ("Frequent", 8, 2),  # 8 rounds, 2 local epochs each
        ("Standard", 4, 4),  # 4 rounds, 4 local epochs each
        ("Infrequent", 2, 8),  # 2 rounds, 8 local epochs each
    ]

    results = {}

    for strategy_name, rounds, local_epochs in communication_strategies:
        print(f"\nTesting {strategy_name} communication...")
        print(
            f"  {rounds} rounds × {local_epochs} local epochs = {rounds * local_epochs} total training"
        )

        # Generate fresh datasets
        datasets = generate_fl_datasets(num_clients=4, samples_per_client=200)

        training_results = federated_training(
            dataset_paths=datasets,
            rounds=rounds,
            local_epochs=local_epochs,
            aggregation="average",
            hidden_size=64,
            hidden_layers=2,
        )

        results[f"{strategy_name} ({rounds}R×{local_epochs}E)"] = training_results[
            "history"
        ]

        final_mse = training_results["final_metrics"]["avg_mse"]
        print(f"Final MSE: {final_mse:.4f}")
        print(f"Total communication rounds: {rounds}")

    # Plot communication efficiency comparison
    output_dir = Path(__file__).parent / "results" / "communication_efficiency"
    output_dir.mkdir(parents=True, exist_ok=True)

    plot_aggregation_comparison(
        results, save_path=output_dir / "communication_efficiency.png"
    )

    print(f"Communication efficiency results saved to: {output_dir}")
    return results


if __name__ == "__main__":
    print("Running Federated Learning Privacy and Communication Experiments")
    print("=" * 70)

    # Privacy experiment
    privacy_results = run_privacy_experiment()

    # Communication efficiency experiment
    comm_results = run_communication_efficiency_experiment()

    print("\n" + "=" * 70)
    print("Privacy and Communication experiments completed!")
    print("\nGenerated plots:")
    print("  - privacy_impact.png: Privacy vs utility tradeoff")
    print("  - privacy_methods_comparison.png: Different privacy levels")
    print("  - communication_efficiency.png: Communication frequency strategies")
    print("\nKey insights for federated learning:")
    print("  - Privacy protection comes with a performance cost")
    print("  - Communication frequency affects convergence patterns")
    print("  - Noise scale should be tuned based on privacy requirements")
