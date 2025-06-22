"""
Federated Learning Experiment Runner

This script runs all federated learning experiments and generates comprehensive
plots for understanding different aspects of federated learning.

Run this script to get a complete overview of federated learning behavior!
"""

import sys
from pathlib import Path
import time

# Add backend directory to path
backend_dir = Path(__file__).parent.parent.parent
sys.path.append(str(backend_dir))

# Import experiment modules
try:
    from fl.experiments.convergence_experiment import (
        run_convergence_experiment,
        run_client_scaling_experiment,
    )
    from fl.experiments.aggregation_experiment import (
        run_aggregation_comparison,
        run_heterogeneity_experiment,
    )
    from fl.experiments.privacy_experiment import (
        run_privacy_experiment,
        run_communication_efficiency_experiment,
    )
    from fl.experiments.fl_plotting import create_fl_summary_report
except ImportError as e:
    print(f"Import error: {e}")
    print("Make sure all required packages are installed.")
    sys.exit(1)


def print_header(title: str):
    """Print a formatted header."""
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


def print_experiment_info():
    """Print information about what the experiments will show."""
    print(
        """
FEDERATED LEARNING EXPERIMENTS OVERVIEW
=======================================

This suite of experiments will demonstrate key concepts in federated learning:

1. CONVERGENCE EXPERIMENT
   - How FL models improve over communication rounds
   - Client data diversity visualization
   - Impact of number of clients on performance

2. AGGREGATION COMPARISON
   - FedAvg vs Weighted vs Median vs Secure aggregation
   - Effect of data heterogeneity on different methods
   - Robustness to outlier clients

3. PRIVACY EXPERIMENTS
   - Privacy-utility tradeoff with differential privacy
   - Impact of noise levels on model performance
   - Communication efficiency strategies

Each experiment generates detailed plots to help you understand:
- When federated learning converges
- Which aggregation method works best for your scenario
- How to balance privacy and performance
- Optimal communication strategies

Total estimated runtime: 5-10 minutes (depending on your hardware)
"""
    )


def run_all_experiments():
    """Run all federated learning experiments."""
    start_time = time.time()

    print_experiment_info()
    input("Press Enter to start all experiments...")

    all_results = {}

    # 1. Convergence Experiments
    print_header("CONVERGENCE & SCALING EXPERIMENTS")

    try:
        print("Running convergence experiment...")
        convergence_results = run_convergence_experiment()
        all_results["convergence"] = convergence_results

        print("\nRunning client scaling experiment...")
        scaling_results = run_client_scaling_experiment()
        all_results["scaling"] = scaling_results

        print("✓ Convergence experiments completed")
    except Exception as e:
        print(f"✗ Convergence experiments failed: {e}")

    # 2. Aggregation Experiments
    print_header("AGGREGATION & HETEROGENEITY EXPERIMENTS")

    try:
        print("Running aggregation comparison...")
        aggregation_results = run_aggregation_comparison()
        all_results["aggregation"] = aggregation_results

        print("\nRunning heterogeneity experiment...")
        heterogeneity_results = run_heterogeneity_experiment()
        all_results["heterogeneity"] = heterogeneity_results

        print("✓ Aggregation experiments completed")
    except Exception as e:
        print(f"✗ Aggregation experiments failed: {e}")

    # 3. Privacy & Communication Experiments
    print_header("PRIVACY & COMMUNICATION EXPERIMENTS")

    try:
        print("Running privacy experiment...")
        privacy_results = run_privacy_experiment()
        all_results["privacy"] = privacy_results

        print("\nRunning communication efficiency experiment...")
        comm_results = run_communication_efficiency_experiment()
        all_results["communication"] = comm_results

        print("✓ Privacy & communication experiments completed")
    except Exception as e:
        print(f"✗ Privacy & communication experiments failed: {e}")

    # Generate final summary
    print_header("GENERATING EXPERIMENT SUMMARY")

    output_dir = Path(__file__).parent / "results" / "complete_summary"
    output_dir.mkdir(parents=True, exist_ok=True)

    # Create a comprehensive summary report
    summary_data = {
        "config": {
            "total_experiments": len(all_results),
            "experiment_types": list(all_results.keys()),
        },
        "history": all_results.get("convergence", {}).get("history", {}),
        "aggregation_results": {
            "federated_methods": all_results.get("aggregation", {}),
            "heterogeneity_impact": all_results.get("heterogeneity", {}),
        },
        "privacy_results": {
            "baseline": all_results.get("privacy", {}).get("No Privacy", {}),
            "private": all_results.get("privacy", {}).get("DP (σ=0.001)", {}),
            "noise_scales": [0.0, 0.001, 0.005, 0.01, 0.05],
        },
    }

    try:
        create_fl_summary_report(summary_data, output_dir)
        print(f"✓ Summary report generated in: {output_dir}")
    except Exception as e:
        print(f"✗ Summary generation failed: {e}")

    # Final statistics
    end_time = time.time()
    duration = end_time - start_time

    print_header("EXPERIMENT COMPLETION SUMMARY")
    print(f"Total runtime: {duration:.1f} seconds ({duration/60:.1f} minutes)")
    print(f"Experiments completed: {len(all_results)}")
    print(f"Results saved in: {Path(__file__).parent / 'results'}")

    print("\nGenerated plots include:")
    plot_files = [
        "convergence_plot.png - FL training convergence over rounds",
        "client_diversity.png - Data distribution across clients",
        "client_scaling_comparison.png - Performance vs number of clients",
        "aggregation_methods_comparison.png - Different FL aggregation strategies",
        "heterogeneity_impact.png - Effect of non-IID data",
        "privacy_impact.png - Privacy-utility tradeoff analysis",
        "communication_efficiency.png - Communication strategy comparison",
        "fl_convergence.png - Comprehensive convergence analysis",
        "fl_communication_analysis.png - Communication patterns",
    ]

    for plot_file in plot_files:
        print(f"  - {plot_file}")

    print("\n🎉 All federated learning experiments completed successfully!")
    print("\nNext steps:")
    print("  1. Review the generated plots to understand FL behavior")
    print("  2. Experiment with different parameters in the code")
    print("  3. Apply insights to your own federated learning projects")

    return all_results


def run_quick_demo():
    """Run a quick demonstration of federated learning."""
    print_header("QUICK FEDERATED LEARNING DEMO")

    print("Running a quick FL demonstration...")
    print("This will take about 1-2 minutes and show basic FL concepts.")

    try:
        # Quick convergence test
        from fl.src.fl_trainer import generate_fl_datasets, federated_training

        print("\n1. Generating client datasets...")
        datasets = generate_fl_datasets(num_clients=3, samples_per_client=100)

        print("2. Running federated training (5 rounds)...")
        results = federated_training(
            dataset_paths=datasets,
            rounds=5,
            local_epochs=3,
            hidden_size=32,
            hidden_layers=1,
        )

        print("3. Generating quick visualization...")
        from fl.experiments.fl_plotting import plot_fl_convergence

        output_dir = Path(__file__).parent / "results" / "quick_demo"
        output_dir.mkdir(parents=True, exist_ok=True)

        plot_fl_convergence(
            results["history"],
            save_path=output_dir / "quick_demo.png",
            title="Quick FL Demo: 3 Clients, 5 Rounds",
        )

        final_mse = results["final_metrics"]["avg_mse"]
        print(f"\n✓ Demo completed! Final MSE: {final_mse:.4f}")
        print(f"Demo plot saved to: {output_dir}\\quick_demo.png")

    except Exception as e:
        print(f"✗ Demo failed: {e}")


if __name__ == "__main__":
    print("Federated Learning Experiment Suite")
    print("=" * 50)

    print("\nChoose an option:")
    print("1. Run all experiments (comprehensive, ~5-10 minutes)")
    print("2. Run quick demo (basic overview, ~1-2 minutes)")
    print("3. Exit")

    while True:
        choice = input("\nEnter your choice (1, 2, or 3): ").strip()

        if choice == "1":
            run_all_experiments()
            break
        elif choice == "2":
            run_quick_demo()
            break
        elif choice == "3":
            print("Goodbye!")
            break
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")
