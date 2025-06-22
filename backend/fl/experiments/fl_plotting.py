"""
Federated Learning Plotting and Visualization Suite

The module provides visualization tools for federated learning experiments,
including convergence plots, client diversity analysis, aggregation method comparisons,
privacy impact analysis, and comprehensive experiment reports.

Functions available:
- plot_fl_convergence: Basic FL convergence plotting
- plot_client_diversity: Client data distribution analysis
- plot_aggregation_comparison: Compare different aggregation methods
- plot_privacy_impact: Analyze differential privacy effects
- plot_communication_rounds: Communication efficiency analysis
- create_beginner_friendly_convergence_plot: Enhanced plots with explanations
- create_client_diversity_dashboard: Interactive-style diversity analysis
- create_aggregation_comparison_plot: Comprehensive aggregation comparison
- create_fl_summary_report: Generate complete experiment reports
- run_comprehensive_fl_experiments: Execute full experiment suite

Utility functions:
- save_experiment_data: Save results to CSV/JSON
- convert_to_json_serializable: Handle numpy data types
- NumpyEncoder: JSON encoder for numpy objects
"""

import sys
import json
import numpy as np
import pandas as pd
import matplotlib
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path
from typing import Dict, List, Any, Optional
import tempfile

# Configure matplotlib backend
matplotlib.use("Agg")

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
except ImportError as e:
    print(f"Import error: {e}")
    print("Make sure all required packages are installed.")
    sys.exit(1)

# Set style for better-looking plots
plt.style.use("seaborn-v0_8")
sns.set_palette("husl")


class NumpyEncoder(json.JSONEncoder):
    """JSON encoder that handles numpy data types."""

    def default(self, obj):
        if isinstance(obj, np.integer):
            return int(obj)
        elif isinstance(obj, np.floating):
            return float(obj)
        elif isinstance(obj, np.ndarray):
            return obj.tolist()
        return super(NumpyEncoder, self).default(obj)


def convert_to_json_serializable(obj):
    """Convert numpy and other non-JSON-serializable objects to JSON-serializable types."""
    if isinstance(obj, np.ndarray):
        return obj.tolist()
    elif isinstance(obj, (np.float32, np.float64)):
        return float(obj)
    elif isinstance(obj, (np.int32, np.int64)):
        return int(obj)
    elif isinstance(obj, dict):
        return {k: convert_to_json_serializable(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_to_json_serializable(item) for item in obj]
    else:
        return obj


# Basic plotting functions
def plot_fl_convergence(
    history: Dict[str, List[float]],
    save_path: Optional[Path] = None,
    title: str = "Federated Learning Convergence",
) -> None:
    """Plot federated learning convergence over rounds.

    Args:
        history: Dictionary with 'rounds', 'global_mse', 'global_mae', etc.
        save_path: Path to save the plot
        title: Plot title
    """
    fig, axes = plt.subplots(2, 2, figsize=(15, 10))
    fig.suptitle(title, fontsize=16, fontweight="bold")

    rounds = history.get("rounds", range(len(history.get("global_mse", []))))

    # Plot MSE convergence
    if "global_mse" in history:
        axes[0, 0].plot(rounds, history["global_mse"], "o-", linewidth=2, markersize=6)
        axes[0, 0].set_title("Global Model MSE")
        axes[0, 0].set_xlabel("Communication Round")
        axes[0, 0].set_ylabel("Mean Squared Error")
        axes[0, 0].grid(True, alpha=0.3)

    # Plot MAE convergence
    if "global_mae" in history:
        axes[0, 1].plot(
            rounds,
            history["global_mae"],
            "o-",
            linewidth=2,
            markersize=6,
            color="orange",
        )
        axes[0, 1].set_title("Global Model MAE")
        axes[0, 1].set_xlabel("Communication Round")
        axes[0, 1].set_ylabel("Mean Absolute Error")
        axes[0, 1].grid(True, alpha=0.3)

    # Plot R² Score
    if "global_r2" in history:
        axes[1, 0].plot(
            rounds, history["global_r2"], "o-", linewidth=2, markersize=6, color="green"
        )
        axes[1, 0].set_title("Global Model R² Score")
        axes[1, 0].set_xlabel("Communication Round")
        axes[1, 0].set_ylabel("R² Score")
        axes[1, 0].grid(True, alpha=0.3)

    # Plot Grade Accuracy if available
    if "global_grade_accuracy" in history:
        axes[1, 1].plot(
            rounds,
            history["global_grade_accuracy"],
            "o-",
            linewidth=2,
            markersize=6,
            color="red",
        )
        axes[1, 1].set_title("Grade Classification Accuracy")
        axes[1, 1].set_xlabel("Communication Round")
        axes[1, 1].set_ylabel("Accuracy")
        axes[1, 1].grid(True, alpha=0.3)
    else:
        # If no grade accuracy, show client participation
        if "participating_clients" in history:
            axes[1, 1].bar(
                rounds, history["participating_clients"], alpha=0.7, color="purple"
            )
            axes[1, 1].set_title("Client Participation")
            axes[1, 1].set_xlabel("Communication Round")
            axes[1, 1].set_ylabel("Number of Clients")
            axes[1, 1].grid(True, alpha=0.3, axis="y")

    plt.tight_layout()

    if save_path:
        plt.savefig(save_path, dpi=300, bbox_inches="tight")
        print(f"Convergence plot saved to {save_path}")

    plt.close()


def plot_client_diversity(
    client_stats: List[Dict[str, Any]], save_path: Optional[Path] = None
) -> None:
    """Plot client data diversity and distribution differences.

    Args:
        client_stats: List of client statistics dictionaries
        save_path: Path to save the plot
    """
    num_clients = len(client_stats)

    fig, axes = plt.subplots(2, 2, figsize=(15, 10))
    fig.suptitle(
        "Federated Learning Client Diversity Analysis", fontsize=16, fontweight="bold"
    )

    # Extract data for plotting
    client_ids = [f"Client {i+1}" for i in range(num_clients)]

    # Data size distribution
    data_sizes = [stats.get("data_size", 0) for stats in client_stats]
    axes[0, 0].bar(client_ids, data_sizes, alpha=0.7, color="skyblue")
    axes[0, 0].set_title("Data Size Distribution Across Clients")
    axes[0, 0].set_ylabel("Number of Samples")
    axes[0, 0].tick_params(axis="x", rotation=45)

    # Target score distribution (if available)
    if all("target_mean" in stats for stats in client_stats):
        target_means = [stats["target_mean"] for stats in client_stats]
        target_stds = [stats.get("target_std", 0) for stats in client_stats]

        axes[0, 1].bar(
            client_ids,
            target_means,
            yerr=target_stds,
            alpha=0.7,
            color="lightcoral",
            capsize=5,
        )
        axes[0, 1].set_title("Target Score Distribution")
        axes[0, 1].set_ylabel("Mean Target Score")
        axes[0, 1].tick_params(axis="x", rotation=45)

    # Grade distribution heatmap (if available)
    if all("grade_distribution" in stats for stats in client_stats):
        grade_data = []
        grade_labels = None

        for stats in client_stats:
            grade_dist = stats["grade_distribution"]
            if grade_labels is None:
                grade_labels = list(grade_dist.keys())
            grade_data.append([grade_dist.get(label, 0) for label in grade_labels])

        im = axes[1, 0].imshow(grade_data, aspect="auto", cmap="YlOrRd")
        axes[1, 0].set_title("Grade Distribution Heatmap")
        axes[1, 0].set_ylabel("Clients")
        axes[1, 0].set_xlabel("Security Grades")
        axes[1, 0].set_yticks(range(num_clients))
        axes[1, 0].set_yticklabels(client_ids)
        axes[1, 0].set_xticks(range(len(grade_labels)))
        axes[1, 0].set_xticklabels(grade_labels, rotation=45)
        plt.colorbar(im, ax=axes[1, 0], label="Count")

    # Feature diversity (coefficient of variation across clients)
    if all("feature_means" in stats for stats in client_stats):
        feature_names = list(client_stats[0]["feature_means"].keys())
        feature_cv = []

        for feature in feature_names:
            values = [stats["feature_means"][feature] for stats in client_stats]
            cv = np.std(values) / np.mean(values) if np.mean(values) != 0 else 0
            feature_cv.append(cv)

        # Show top 10 most diverse features
        top_indices = np.argsort(feature_cv)[-10:]
        top_features = [feature_names[i] for i in top_indices]
        top_cv = [feature_cv[i] for i in top_indices]

        axes[1, 1].barh(top_features, top_cv, alpha=0.7, color="lightgreen")
        axes[1, 1].set_title("Feature Diversity (Top 10)")
        axes[1, 1].set_xlabel("Coefficient of Variation")

    plt.tight_layout()

    if save_path:
        plt.savefig(save_path, dpi=300, bbox_inches="tight")
        print(f"Client diversity plot saved to {save_path}")


def plot_aggregation_comparison(
    results: Dict[str, Dict[str, List[float]]], save_path: Optional[Path] = None
) -> None:
    """Compare different aggregation methods.

    Args:
        results: Dictionary mapping method names to their training histories
        save_path: Path to save the plot
    """
    fig, axes = plt.subplots(2, 2, figsize=(15, 10))
    fig.suptitle(
        "Federated Learning Aggregation Methods Comparison",
        fontsize=16,
        fontweight="bold",
    )

    methods = list(results.keys())
    colors = plt.cm.Set1(np.linspace(0, 1, len(methods)))

    for i, (method, history) in enumerate(results.items()):
        color = colors[i]
        rounds = history.get("rounds", range(len(history.get("global_mse", []))))

        # MSE comparison
        if "global_mse" in history:
            axes[0, 0].plot(
                rounds,
                history["global_mse"],
                "o-",
                label=method,
                color=color,
                linewidth=2,
                markersize=4,
            )

        # MAE comparison
        if "global_mae" in history:
            axes[0, 1].plot(
                rounds,
                history["global_mae"],
                "o-",
                label=method,
                color=color,
                linewidth=2,
                markersize=4,
            )

        # R² comparison
        if "global_r2" in history:
            axes[1, 0].plot(
                rounds,
                history["global_r2"],
                "o-",
                label=method,
                color=color,
                linewidth=2,
                markersize=4,
            )

        # Convergence speed (final performance)
        if "global_mse" in history and len(history["global_mse"]) > 0:
            final_mse = history["global_mse"][-1]
            axes[1, 1].bar(method, final_mse, alpha=0.7, color=color)

    axes[0, 0].set_title("MSE Convergence")
    axes[0, 0].set_xlabel("Communication Round")
    axes[0, 0].set_ylabel("MSE")
    axes[0, 0].legend()
    axes[0, 0].grid(True, alpha=0.3)

    axes[0, 1].set_title("MAE Convergence")
    axes[0, 1].set_xlabel("Communication Round")
    axes[0, 1].set_ylabel("MAE")
    axes[0, 1].legend()
    axes[0, 1].grid(True, alpha=0.3)

    axes[1, 0].set_title("R² Score Convergence")
    axes[1, 0].set_xlabel("Communication Round")
    axes[1, 0].set_ylabel("R² Score")
    axes[1, 0].legend()
    axes[1, 0].grid(True, alpha=0.3)

    axes[1, 1].set_title("Final MSE Performance")
    axes[1, 1].set_ylabel("Final MSE")
    axes[1, 1].tick_params(axis="x", rotation=45)

    plt.tight_layout()

    if save_path:
        plt.savefig(save_path, dpi=300, bbox_inches="tight")
        print(f"Aggregation comparison plot saved to {save_path}")


def plot_privacy_impact(
    baseline_history: Dict[str, List[float]],
    private_history: Dict[str, List[float]],
    noise_scales: List[float],
    save_path: Optional[Path] = None,
) -> None:
    """Plot the impact of differential privacy on model performance.

    Args:
        baseline_history: Training history without privacy
        private_history: Training history with differential privacy
        noise_scales: List of noise scales tested
        save_path: Path to save the plot
    """
    fig, axes = plt.subplots(2, 2, figsize=(15, 10))
    fig.suptitle(
        "Differential Privacy Impact on Federated Learning",
        fontsize=16,
        fontweight="bold",
    )

    rounds = baseline_history.get(
        "rounds", range(len(baseline_history.get("global_mse", [])))
    )

    # MSE comparison
    if "global_mse" in baseline_history and "global_mse" in private_history:
        axes[0, 0].plot(
            rounds,
            baseline_history["global_mse"],
            "o-",
            label="No Privacy",
            linewidth=2,
            markersize=6,
        )
        axes[0, 0].plot(
            rounds,
            private_history["global_mse"],
            "s-",
            label="With DP",
            linewidth=2,
            markersize=6,
        )
        axes[0, 0].set_title("MSE: Privacy vs No Privacy")
        axes[0, 0].set_xlabel("Communication Round")
        axes[0, 0].set_ylabel("MSE")
        axes[0, 0].legend()
        axes[0, 0].grid(True, alpha=0.3)

    # Privacy-utility tradeoff
    if len(noise_scales) > 1:
        # This would be filled with results from multiple noise scale experiments
        # For now, show conceptual relationship
        utility_loss = [0.1 * scale for scale in noise_scales]  # Placeholder
        axes[0, 1].plot(
            noise_scales, utility_loss, "o-", linewidth=2, markersize=6, color="red"
        )
        axes[0, 1].set_title("Privacy-Utility Tradeoff")
        axes[0, 1].set_xlabel("Noise Scale (ε⁻¹)")
        axes[0, 1].set_ylabel("Utility Loss (MSE increase)")
        axes[0, 1].grid(True, alpha=0.3)

    # Model similarity over rounds (privacy impact on aggregation)
    if "model_similarity" in baseline_history and "model_similarity" in private_history:
        axes[1, 0].plot(
            rounds,
            baseline_history["model_similarity"],
            "o-",
            label="No Privacy",
            linewidth=2,
            markersize=6,
        )
        axes[1, 0].plot(
            rounds,
            private_history["model_similarity"],
            "s-",
            label="With DP",
            linewidth=2,
            markersize=6,
        )
        axes[1, 0].set_title("Model Similarity Between Clients")
        axes[1, 0].set_xlabel("Communication Round")
        axes[1, 0].set_ylabel("Average Cosine Similarity")
        axes[1, 0].legend()
        axes[1, 0].grid(True, alpha=0.3)

    # Communication efficiency (convergence speed)
    if "global_mse" in baseline_history and "global_mse" in private_history:
        # Calculate convergence metrics
        baseline_convergence = np.gradient(baseline_history["global_mse"])
        private_convergence = np.gradient(private_history["global_mse"])

        axes[1, 1].plot(
            rounds, np.abs(baseline_convergence), label="No Privacy", linewidth=2
        )
        axes[1, 1].plot(
            rounds, np.abs(private_convergence), label="With DP", linewidth=2
        )
        axes[1, 1].set_title("Convergence Speed (|dMSE/dRound|)")
        axes[1, 1].set_xlabel("Communication Round")
        axes[1, 1].set_ylabel("Absolute MSE Gradient")
        axes[1, 1].legend()
        axes[1, 1].grid(True, alpha=0.3)

    plt.tight_layout()

    if save_path:
        plt.savefig(save_path, dpi=300, bbox_inches="tight")
        print(f"Privacy impact plot saved to {save_path}")


def plot_communication_rounds(
    history: Dict[str, List[float]], save_path: Optional[Path] = None
) -> None:
    """Plot communication efficiency and model updates over rounds.

    Args:
        history: Training history with communication metrics
        save_path: Path to save the plot
    """
    fig, axes = plt.subplots(2, 2, figsize=(15, 10))
    fig.suptitle(
        "Federated Learning Communication Analysis", fontsize=16, fontweight="bold"
    )

    rounds = history.get("rounds", range(len(history.get("global_mse", []))))

    # Model update magnitude
    if "update_magnitude" in history:
        axes[0, 0].plot(
            rounds, history["update_magnitude"], "o-", linewidth=2, markersize=6
        )
        axes[0, 0].set_title("Model Update Magnitude")
        axes[0, 0].set_xlabel("Communication Round")
        axes[0, 0].set_ylabel("L2 Norm of Updates")
        axes[0, 0].grid(True, alpha=0.3)

    # Client similarity over time
    if "client_similarity" in history and history["client_similarity"]:
        # client_similarity is structured as [round][client] = similarity
        # We need to transpose it to [client][round] = similarity
        num_clients = (
            len(history["client_similarity"][0]) if history["client_similarity"] else 0
        )

        if num_clients > 0:
            for client_idx in range(num_clients):
                client_similarities = [
                    round_similarities[client_idx]
                    for round_similarities in history["client_similarity"]
                ]
                axes[0, 1].plot(
                    rounds,
                    client_similarities,
                    label=f"Client {client_idx+1}",
                    linewidth=2,
                )

            axes[0, 1].set_title("Client Model Similarity to Global")
            axes[0, 1].set_xlabel("Communication Round")
            axes[0, 1].set_ylabel("Cosine Similarity")
            axes[0, 1].legend()
            axes[0, 1].grid(True, alpha=0.3)
        else:
            # If no client similarity data, show placeholder
            axes[0, 1].text(
                0.5,
                0.5,
                "No client similarity data available",
                transform=axes[0, 1].transAxes,
                ha="center",
                va="center",
            )
            axes[0, 1].set_title("Client Model Similarity (N/A)")
    else:
        # If no client similarity data, show placeholder
        axes[0, 1].text(
            0.5,
            0.5,
            "No client similarity data available",
            transform=axes[0, 1].transAxes,
            ha="center",
            va="center",
        )
        axes[0, 1].set_title("Client Model Similarity (N/A)")

    # Training efficiency (performance per round)
    if "global_mse" in history and len(history["global_mse"]) > 1:
        initial_mse = history["global_mse"][0]
        efficiency = [
            (initial_mse - mse) / (r + 1) for r, mse in enumerate(history["global_mse"])
        ]
        axes[1, 0].plot(
            rounds, efficiency, "o-", linewidth=2, markersize=6, color="green"
        )
        axes[1, 0].set_title("Training Efficiency (Improvement per Round)")
        axes[1, 0].set_xlabel("Communication Round")
        axes[1, 0].set_ylabel("MSE Improvement per Round")
        axes[1, 0].grid(True, alpha=0.3)

    # Communication cost vs performance
    if "global_mse" in history:
        # Simulate communication cost (proportional to rounds)
        comm_cost = np.cumsum([1] * len(rounds))  # Linear increase
        performance = [
            1 / (mse + 0.001) for mse in history["global_mse"]
        ]  # Inverse MSE

        axes[1, 1].plot(
            comm_cost, performance, "o-", linewidth=2, markersize=6, color="purple"
        )
        axes[1, 1].set_title("Performance vs Communication Cost")
        axes[1, 1].set_xlabel("Cumulative Communication Rounds")
        axes[1, 1].set_ylabel("Performance (1/MSE)")
        axes[1, 1].grid(True, alpha=0.3)

    plt.tight_layout()

    if save_path:
        plt.savefig(save_path, dpi=300, bbox_inches="tight")
        print(f"Communication analysis plot saved to {save_path}")


# Enhanced beginner-friendly plotting functions


def create_beginner_friendly_convergence_plot(
    history: Dict[str, List[float]],
    save_path: Optional[Path] = None,
    title: str = "Your First Federated Learning Experiment!",
) -> None:
    """Create a beginner-friendly convergence plot with explanations.

    Args:
        history: Training history dictionary
        save_path: Path to save the plot
        title: Plot title
    """
    fig, axes = plt.subplots(2, 2, figsize=(16, 12))
    fig.suptitle(title, fontsize=18, fontweight="bold", y=0.95)

    rounds = history.get("rounds", range(len(history.get("global_mse", []))))

    # Plot 1: MSE - The main performance metric
    if "global_mse" in history:
        axes[0, 0].plot(
            rounds,
            history["global_mse"],
            "o-",
            linewidth=3,
            markersize=8,
            color="#e74c3c",
        )
        axes[0, 0].set_title(
            "🎯 Model Performance (Lower = Better)", fontsize=14, fontweight="bold"
        )
        axes[0, 0].set_xlabel("Communication Round", fontsize=12)
        axes[0, 0].set_ylabel("Mean Squared Error (MSE)", fontsize=12)
        axes[0, 0].grid(True, alpha=0.3)

        # Add trend annotation
        if len(history["global_mse"]) > 1:
            improvement = history["global_mse"][0] - history["global_mse"][-1]
            improvement_pct = (improvement / history["global_mse"][0]) * 100
            axes[0, 0].text(
                0.02,
                0.98,
                f"Improvement: {improvement_pct:.1f}%",
                transform=axes[0, 0].transAxes,
                fontsize=10,
                bbox=dict(boxstyle="round,pad=0.3", facecolor="lightgreen", alpha=0.8),
                verticalalignment="top",
            )

    # Plot 2: R² Score - How well the model explains the data
    if "global_r2" in history:
        axes[0, 1].plot(
            rounds,
            history["global_r2"],
            "o-",
            linewidth=3,
            markersize=8,
            color="#2ecc71",
        )
        axes[0, 1].set_title(
            "📊 Model Fit Quality (Higher = Better)", fontsize=14, fontweight="bold"
        )
        axes[0, 1].set_xlabel("Communication Round", fontsize=12)
        axes[0, 1].set_ylabel("R² Score (0=random, 1=perfect)", fontsize=12)
        axes[0, 1].grid(True, alpha=0.3)
        axes[0, 1].axhline(
            y=0, color="red", linestyle="--", alpha=0.5, label="Random performance"
        )
        axes[0, 1].axhline(
            y=1, color="green", linestyle="--", alpha=0.5, label="Perfect performance"
        )
        axes[0, 1].legend()

    # Plot 3: Client Collaboration - How similar client models become
    if "model_similarity" in history:
        axes[1, 0].plot(
            rounds,
            history["model_similarity"],
            "o-",
            linewidth=3,
            markersize=8,
            color="#3498db",
        )
        axes[1, 0].set_title(
            "🤝 Client Collaboration (Higher = More Similar)",
            fontsize=14,
            fontweight="bold",
        )
        axes[1, 0].set_xlabel("Communication Round", fontsize=12)
        axes[1, 0].set_ylabel("Model Similarity (0-1)", fontsize=12)
        axes[1, 0].grid(True, alpha=0.3)
        axes[1, 0].axhline(
            y=0.5, color="orange", linestyle="--", alpha=0.5, label="50% similarity"
        )
        axes[1, 0].legend()

    # Plot 4: Learning Progress - How much models change each round
    if "update_magnitude" in history:
        axes[1, 1].plot(
            rounds,
            history["update_magnitude"],
            "o-",
            linewidth=3,
            markersize=8,
            color="#9b59b6",
        )
        axes[1, 1].set_title(
            "🔄 Learning Activity (How Much Models Change)",
            fontsize=14,
            fontweight="bold",
        )
        axes[1, 1].set_xlabel("Communication Round", fontsize=12)
        axes[1, 1].set_ylabel("Update Magnitude", fontsize=12)
        axes[1, 1].grid(True, alpha=0.3)

    plt.tight_layout()

    # Add explanatory text box
    explanation = """
    📚 What you're seeing:
    • Top Left: Model accuracy improves as MSE decreases
    • Top Right: R² shows how well the model explains data (closer to 1 is better)
    • Bottom Left: Clients learn to work together (models become more similar)
    • Bottom Right: Learning activity (high at start, stabilizes when converged)
    """

    fig.text(
        0.02,
        0.02,
        explanation,
        fontsize=10,
        bbox=dict(boxstyle="round,pad=0.5", facecolor="lightblue", alpha=0.8),
        verticalalignment="bottom",
    )

    if save_path:
        plt.savefig(save_path, dpi=300, bbox_inches="tight")
        print(f"🎨 Beginner-friendly convergence plot saved to {save_path}")

    plt.show()


def create_client_diversity_dashboard(
    client_stats: List[Dict[str, Any]], save_path: Optional[Path] = None
) -> None:
    """Create an interactive-style dashboard showing client diversity.

    Args:
        client_stats: List of client statistics
        save_path: Path to save the plot
    """
    num_clients = len(client_stats)
    fig, axes = plt.subplots(2, 3, figsize=(20, 12))
    fig.suptitle(
        "🏢 Federated Learning Client Diversity Dashboard",
        fontsize=18,
        fontweight="bold",
    )

    client_ids = [f"Client {i+1}" for i in range(num_clients)]
    colors = plt.cm.Set3(np.linspace(0, 1, num_clients))

    # 1. Data Size Distribution
    data_sizes = [stats.get("data_size", 0) for stats in client_stats]
    bars1 = axes[0, 0].bar(client_ids, data_sizes, color=colors, alpha=0.8)
    axes[0, 0].set_title("📊 Data Size per Client", fontsize=14, fontweight="bold")
    axes[0, 0].set_ylabel("Number of Samples")
    axes[0, 0].tick_params(axis="x", rotation=45)

    # Add value labels on bars
    for bar, size in zip(bars1, data_sizes):
        height = bar.get_height()
        axes[0, 0].text(
            bar.get_x() + bar.get_width() / 2.0,
            height + 5,
            f"{size}",
            ha="center",
            va="bottom",
            fontweight="bold",
        )

    # 2. Target Score Distribution
    if all("target_mean" in stats for stats in client_stats):
        target_means = [stats["target_mean"] for stats in client_stats]
        target_stds = [stats.get("target_std", 0) for stats in client_stats]

        bars2 = axes[0, 1].bar(
            client_ids,
            target_means,
            yerr=target_stds,
            color=colors,
            alpha=0.8,
            capsize=5,
        )
        axes[0, 1].set_title(
            "🎯 Average Security Scores", fontsize=14, fontweight="bold"
        )
        axes[0, 1].set_ylabel("Mean Target Score")
        axes[0, 1].tick_params(axis="x", rotation=45)

        # Add value labels
        for bar, mean in zip(bars2, target_means):
            height = bar.get_height()
            axes[0, 1].text(
                bar.get_x() + bar.get_width() / 2.0,
                height + 1,
                f"{mean:.1f}",
                ha="center",
                va="bottom",
                fontweight="bold",
            )

    # 3. Grade Distribution Pie Chart
    if all("grade_distribution" in stats for stats in client_stats):
        # Aggregate all grades across clients
        all_grades = {}
        for stats in client_stats:
            for grade, count in stats["grade_distribution"].items():
                all_grades[grade] = all_grades.get(grade, 0) + count

        # Create pie chart
        grades = list(all_grades.keys())
        counts = list(all_grades.values())
        grade_colors = {
            "Excellent": "#27ae60",
            "Good": "#2ecc71",
            "Fair": "#f39c12",
            "Poor": "#e74c3c",
            "Critical Risk": "#8e44ad",
        }
        pie_colors = [grade_colors.get(grade, "#95a5a6") for grade in grades]

        wedges, texts, autotexts = axes[0, 2].pie(
            counts, labels=grades, autopct="%1.1f%%", colors=pie_colors, startangle=90
        )
        axes[0, 2].set_title(
            "🏆 Overall Grade Distribution", fontsize=14, fontweight="bold"
        )

    # 4. Client Grade Comparison (Stacked Bar)
    if all("grade_distribution" in stats for stats in client_stats):
        grade_data = {}
        all_grade_types = set()

        for stats in client_stats:
            all_grade_types.update(stats["grade_distribution"].keys())

        for grade in all_grade_types:
            grade_data[grade] = [
                stats["grade_distribution"].get(grade, 0) for stats in client_stats
            ]

        bottom = np.zeros(num_clients)
        for grade, counts in grade_data.items():
            color = grade_colors.get(grade, "#95a5a6")
            axes[1, 0].bar(
                client_ids, counts, bottom=bottom, label=grade, color=color, alpha=0.8
            )
            bottom += counts

        axes[1, 0].set_title(
            "📈 Grade Distribution by Client", fontsize=14, fontweight="bold"
        )
        axes[1, 0].set_ylabel("Number of Samples")
        axes[1, 0].tick_params(axis="x", rotation=45)
        axes[1, 0].legend(bbox_to_anchor=(1.05, 1), loc="upper left")

    # 5. Data Heterogeneity Heatmap
    if all("feature_means" in stats for stats in client_stats):
        feature_names = list(client_stats[0]["feature_means"].keys())
        # Take first 10 features for readability
        feature_names = feature_names[:10]

        feature_matrix = []
        for stats in client_stats:
            row = [stats["feature_means"].get(feature, 0) for feature in feature_names]
            feature_matrix.append(row)

        # Normalize each feature across clients
        feature_matrix = np.array(feature_matrix)
        feature_matrix_norm = (feature_matrix - feature_matrix.mean(axis=0)) / (
            feature_matrix.std(axis=0) + 1e-8
        )

        im = axes[1, 1].imshow(
            feature_matrix_norm.T, aspect="auto", cmap="RdBu_r", vmin=-2, vmax=2
        )
        axes[1, 1].set_title(
            "🌡️ Feature Diversity Heatmap", fontsize=14, fontweight="bold"
        )
        axes[1, 1].set_xlabel("Clients")
        axes[1, 1].set_ylabel("Features (Top 10)")
        axes[1, 1].set_xticks(range(num_clients))
        axes[1, 1].set_xticklabels(client_ids)
        axes[1, 1].set_yticks(range(len(feature_names)))
        axes[1, 1].set_yticklabels(
            [name[:15] + "..." if len(name) > 15 else name for name in feature_names],
            fontsize=8,
        )

        cbar = plt.colorbar(im, ax=axes[1, 1])
        cbar.set_label("Normalized Feature Value", rotation=270, labelpad=15)

    # 6. Summary Statistics
    axes[1, 2].axis("off")
    summary_text = f"""
    📋 DIVERSITY SUMMARY

    👥 Number of Clients: {num_clients}
    📊 Total Samples: {sum(data_sizes)}
    📈 Avg Samples/Client: {np.mean(data_sizes):.0f}
    📉 Min Samples: {min(data_sizes)}
    📈 Max Samples: {max(data_sizes)}

    🎯 Data Heterogeneity:
    """

    if all("target_mean" in stats for stats in client_stats):
        target_means = [stats["target_mean"] for stats in client_stats]
        target_cv = np.std(target_means) / np.mean(target_means)
        summary_text += f"• Target Score CV: {target_cv:.3f}\n"
        summary_text += (
            f"• Score Range: {min(target_means):.1f} - {max(target_means):.1f}\n"
        )

    summary_text += """
    💡 Understanding Diversity:
    • Higher diversity = more realistic FL
    • Lower diversity = easier convergence
    • Balanced diversity = optimal learning
    """

    axes[1, 2].text(
        0.1,
        0.9,
        summary_text,
        transform=axes[1, 2].transAxes,
        fontsize=11,
        verticalalignment="top",
        bbox=dict(boxstyle="round,pad=0.5", facecolor="lightyellow", alpha=0.8),
    )

    plt.tight_layout()

    if save_path:
        plt.savefig(save_path, dpi=300, bbox_inches="tight")
        print(f"🎨 Client diversity dashboard saved to {save_path}")

    plt.show()


def create_aggregation_comparison_plot(
    aggregation_results: Dict[str, Dict[str, Any]], save_path: Optional[Path] = None
) -> None:
    """Create a comprehensive comparison of aggregation methods.

    Args:
        aggregation_results: Results from different aggregation methods
        save_path: Path to save the plot
    """
    fig, axes = plt.subplots(2, 3, figsize=(20, 12))
    fig.suptitle(
        "⚖️ Federated Learning Aggregation Methods Battle!",
        fontsize=18,
        fontweight="bold",
    )

    methods = list(aggregation_results.keys())
    colors = plt.cm.Dark2(np.linspace(0, 1, len(methods)))
    method_colors = dict(zip(methods, colors))

    # Method descriptions for beginners
    method_descriptions = {
        "average": "Simple Average\n(Equal weight to all clients)",
        "weighted": "Weighted Average\n(Larger datasets get more influence)",
        "median": "Median Aggregation\n(Robust to outlier clients)",
        "secure": "Secure Aggregation\n(With privacy protection)",
    }

    # 1. MSE Convergence Race
    for method, results in aggregation_results.items():
        if "history" in results and "global_mse" in results["history"]:
            history = results["history"]
            rounds = history.get("rounds", range(len(history.get("global_mse", []))))
            color = method_colors[method]
            axes[0, 0].plot(
                rounds,
                history["global_mse"],
                "o-",
                label=method_descriptions.get(method, method),
                color=color,
                linewidth=3,
                markersize=6,
            )

    axes[0, 0].set_title("🏁 MSE Convergence Race", fontsize=14, fontweight="bold")
    axes[0, 0].set_xlabel("Communication Round")
    axes[0, 0].set_ylabel("Mean Squared Error")
    axes[0, 0].legend()
    axes[0, 0].grid(True, alpha=0.3)

    # 2. Final Performance Comparison
    final_performance = {}
    for method, results in aggregation_results.items():
        if "final_metrics" in results:
            final_performance[method] = results["final_metrics"].get(
                "avg_mse", float("inf")
            )
        elif "history" in results and "global_mse" in results["history"]:
            final_performance[method] = results["history"]["global_mse"][-1]

    if final_performance:
        methods_sorted = sorted(
            final_performance.keys(), key=lambda x: final_performance[x]
        )
        bars = axes[0, 1].bar(
            range(len(methods_sorted)),
            [final_performance[m] for m in methods_sorted],
            color=[method_colors[m] for m in methods_sorted],
            alpha=0.8,
        )
        axes[0, 1].set_title(
            "🏆 Final Performance Ranking", fontsize=14, fontweight="bold"
        )
        axes[0, 1].set_ylabel("Final MSE (Lower = Better)")
        axes[0, 1].set_xticks(range(len(methods_sorted)))
        axes[0, 1].set_xticklabels(methods_sorted, rotation=45)

        # Add value labels and ranking
        for i, (bar, method) in enumerate(zip(bars, methods_sorted)):
            height = bar.get_height()
            axes[0, 1].text(
                bar.get_x() + bar.get_width() / 2.0,
                height,
                f"#{i+1}\n{height:.1f}",
                ha="center",
                va="bottom",
                fontweight="bold",
            )

    # 3. Convergence Speed
    convergence_speeds = {}
    for method, results in aggregation_results.items():
        if "history" in results and "global_mse" in results["history"]:
            mse_values = results["history"]["global_mse"]
            if len(mse_values) > 1:
                # Find round where improvement becomes minimal (convergence)
                improvements = [
                    mse_values[i] - mse_values[i + 1]
                    for i in range(len(mse_values) - 1)
                ]
                threshold = max(improvements) * 0.1  # 10% of max improvement
                convergence_round = next(
                    (i for i, imp in enumerate(improvements) if imp < threshold),
                    len(improvements),
                )
                convergence_speeds[method] = convergence_round + 1

    if convergence_speeds:
        bars = axes[0, 2].bar(
            convergence_speeds.keys(),
            convergence_speeds.values(),
            color=[method_colors[m] for m in convergence_speeds.keys()],
            alpha=0.8,
        )
        axes[0, 2].set_title("⚡ Convergence Speed", fontsize=14, fontweight="bold")
        axes[0, 2].set_ylabel("Rounds to Convergence")
        axes[0, 2].tick_params(axis="x", rotation=45)

        # Add value labels
        for bar in bars:
            height = bar.get_height()
            axes[0, 2].text(
                bar.get_x() + bar.get_width() / 2.0,
                height,
                f"{int(height)}",
                ha="center",
                va="bottom",
                fontweight="bold",
            )

    # 4. R² Score Comparison
    for method, results in aggregation_results.items():
        if "history" in results and "global_r2" in results["history"]:
            history = results["history"]
            rounds = history.get("rounds", range(len(history.get("global_r2", []))))
            color = method_colors[method]
            axes[1, 0].plot(
                rounds,
                history["global_r2"],
                "o-",
                label=method,
                color=color,
                linewidth=3,
                markersize=6,
            )

    axes[1, 0].set_title("📊 R² Score Evolution", fontsize=14, fontweight="bold")
    axes[1, 0].set_xlabel("Communication Round")
    axes[1, 0].set_ylabel("R² Score (Higher = Better)")
    axes[1, 0].legend()
    axes[1, 0].grid(True, alpha=0.3)
    axes[1, 0].axhline(
        y=0.5, color="red", linestyle="--", alpha=0.5, label="Good performance"
    )

    # 5. Method Guide
    axes[1, 1].axis("off")
    stability_text = """
    🔍 AGGREGATION METHOD GUIDE

    📊 SIMPLE AVERAGE:
    ✅ Easy to understand
    ✅ Works well with similar clients
    ❌ Sensitive to outliers

    ⚖️ WEIGHTED AVERAGE:
    ✅ Considers data size
    ✅ More democratic
    ❌ Large clients dominate

    🛡️ MEDIAN:
    ✅ Robust to attacks
    ✅ Handles outliers well
    ❌ May lose information

    🔒 SECURE:
    ✅ Privacy protection
    ✅ Secure computation
    ❌ Higher computation cost
    """

    axes[1, 1].text(
        0.1,
        0.9,
        stability_text,
        transform=axes[1, 1].transAxes,
        fontsize=10,
        verticalalignment="top",
        bbox=dict(boxstyle="round,pad=0.5", facecolor="lightcyan", alpha=0.8),
    )

    # 6. Recommendation System
    axes[1, 2].axis("off")

    # Determine best method based on performance
    if final_performance:
        best_method = min(final_performance.keys(), key=lambda x: final_performance[x])
        best_mse = final_performance[best_method]

        recommendation_text = f"""
        🎖️ WINNER: {best_method.upper()}

        🏆 Best Performance: {best_mse:.1f} MSE

        📋 RECOMMENDATIONS:

        For Beginners: Start with 'average'
        For Unequal Data: Use 'weighted'
        For Security: Choose 'secure'
        For Robustness: Pick 'median'

        💡 Your best method achieved
        {((max(final_performance.values()) - best_mse) / max(final_performance.values()) * 100):.1f}%
        better performance than the worst!
        """
    else:
        recommendation_text = """
        📋 RECOMMENDATIONS:

        For Beginners: Start with 'average'
        For Unequal Data: Use 'weighted'
        For Security: Choose 'secure'
        For Robustness: Pick 'median'

        💡 Try different methods to see
        which works best for your data!
        """

    axes[1, 2].text(
        0.1,
        0.9,
        recommendation_text,
        transform=axes[1, 2].transAxes,
        fontsize=11,
        verticalalignment="top",
        bbox=dict(boxstyle="round,pad=0.5", facecolor="lightgreen", alpha=0.8),
    )

    plt.tight_layout()

    if save_path:
        plt.savefig(save_path, dpi=300, bbox_inches="tight")
        print(f"🎨 Aggregation comparison plot saved to {save_path}")

    plt.show()


# Comprehensive experiment and summary functions


def create_fl_summary_report(
    experiment_results: Dict[str, Any], output_dir: Path
) -> None:
    """Create a comprehensive summary report with all plots.

    Args:
        experiment_results: Dictionary containing all experiment data
        output_dir: Directory to save all plots and report
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    print("Generating Federated Learning Summary Report...")
    print("=" * 50)

    # Plot 1: Main convergence
    if "history" in experiment_results:
        plot_fl_convergence(
            experiment_results["history"],
            save_path=output_dir / "fl_convergence.png",
            title="Federated Learning Training Convergence",
        )

    # Plot 2: Client diversity
    if "client_stats" in experiment_results:
        plot_client_diversity(
            experiment_results["client_stats"],
            save_path=output_dir / "fl_client_diversity.png",
        )

    # Plot 3: Aggregation comparison (if multiple methods tested)
    if "aggregation_results" in experiment_results:
        plot_aggregation_comparison(
            experiment_results["aggregation_results"],
            save_path=output_dir / "fl_aggregation_comparison.png",
        )

    # Plot 4: Privacy impact (if privacy experiments conducted)
    if "privacy_results" in experiment_results:
        privacy_data = experiment_results["privacy_results"]
        plot_privacy_impact(
            privacy_data.get("baseline", {}),
            privacy_data.get("private", {}),
            privacy_data.get("noise_scales", [0.001]),
            save_path=output_dir / "fl_privacy_impact.png",
        )

    # Plot 5: Communication analysis
    if "history" in experiment_results:
        plot_communication_rounds(
            experiment_results["history"],
            save_path=output_dir / "fl_communication_analysis.png",
        )

    print(f"\nAll plots saved to: {output_dir}")
    print("Summary report generation complete!")


def save_experiment_data(experiment_results: Dict[str, Any], output_path: Path) -> None:
    """Save experiment data to CSV and JSON files.

    Args:
        experiment_results: All experiment data
        output_path: Directory to save data files
    """
    output_path.mkdir(parents=True, exist_ok=True)

    # Save training history as CSV
    if "history" in experiment_results:
        df = pd.DataFrame(experiment_results["history"])
        df.to_csv(output_path / "fl_training_history.csv", index=False)

    # Save configuration and metadata as JSON
    config = {
        "config": experiment_results.get("config", {}),
        "final_metrics": experiment_results.get("final_metrics", {}),
        "experiment_info": {
            "total_rounds": len(
                experiment_results.get("history", {}).get("rounds", [])
            ),
            "num_clients": experiment_results.get("config", {}).get("num_clients", 0),
            "aggregation_method": experiment_results.get("config", {}).get(
                "aggregation", "unknown"
            ),
        },
    }

    # Convert to JSON-serializable format
    config = convert_to_json_serializable(config)

    with open(output_path / "fl_experiment_summary.json", "w") as f:
        json.dump(config, f, indent=2)

    print(f"Experiment data saved to {output_path}")


def run_comprehensive_fl_experiments():
    """Run comprehensive FL experiments with enhanced visualizations."""
    print("🚀 Starting Comprehensive Federated Learning Experiments!")
    print("=" * 60)

    # Create results directory
    results_dir = Path(__file__).parent / "results" / "enhanced_experiments"
    results_dir.mkdir(parents=True, exist_ok=True)

    # Experiment 1: Basic Convergence with Different Client Counts
    print("\n📊 Experiment 1: Client Scaling Analysis")
    client_scaling_results = {}

    for num_clients in [2, 4, 6]:
        print(f"  Testing with {num_clients} clients...")

        config = create_federated_experiment_config(
            num_clients=num_clients,
            samples_per_client=150,
            rounds=10,
            local_epochs=3,
            aggregation="average",
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            # Generate datasets
            datasets = generate_fl_datasets(
                num_clients=num_clients, samples_per_client=150, output_dir=temp_dir
            )

            # Run training
            history = federated_training(
                dataset_paths=datasets, rounds=10, local_epochs=3, verbose=False
            )

            client_scaling_results[f"{num_clients}_clients"] = {
                "history": history,
                "config": config,
            }

    # Create client scaling plot
    fig, ax = plt.subplots(figsize=(12, 8))
    for experiment, results in client_scaling_results.items():
        history = results["history"]
        rounds = history.get("rounds", range(len(history.get("global_mse", []))))
        ax.plot(
            rounds,
            history["global_mse"],
            "o-",
            linewidth=3,
            markersize=6,
            label=experiment.replace("_", " ").title(),
        )

    ax.set_title(
        "🔢 How Number of Clients Affects Learning", fontsize=16, fontweight="bold"
    )
    ax.set_xlabel("Communication Round", fontsize=12)
    ax.set_ylabel("Mean Squared Error", fontsize=12)
    ax.legend()
    ax.grid(True, alpha=0.3)

    plt.tight_layout()
    plt.savefig(
        results_dir / "client_scaling_comparison.png", dpi=300, bbox_inches="tight"
    )
    print("🎨 Client scaling plot saved")
    plt.show()

    # Experiment 2: Aggregation Method Comparison
    print("\n⚖️ Experiment 2: Aggregation Methods Battle")
    aggregation_methods = ["average", "weighted", "median"]
    aggregation_results = {}

    for method in aggregation_methods:
        print(f"  Testing {method} aggregation...")

        config = create_federated_experiment_config(
            num_clients=4,
            samples_per_client=150,
            rounds=8,
            local_epochs=3,
            aggregation=method,
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            datasets = generate_fl_datasets(
                num_clients=4, samples_per_client=150, output_dir=temp_dir
            )

            history = federated_training(
                dataset_paths=datasets,
                rounds=8,
                local_epochs=3,
                aggregation=method,
                verbose=False,
            )

            aggregation_results[method] = {
                "history": history,
                "config": config,
                "final_metrics": {
                    "avg_mse": (
                        history["global_mse"][-1]
                        if history["global_mse"]
                        else float("inf")
                    )
                },
            }

    # Create aggregation comparison
    create_aggregation_comparison_plot(
        aggregation_results,
        save_path=results_dir / "aggregation_methods_comparison.png",
    )

    # Experiment 3: Detailed Analysis with Best Method
    print("\n🔬 Experiment 3: Detailed Analysis")

    # Find best aggregation method
    best_method = min(
        aggregation_results.keys(),
        key=lambda x: aggregation_results[x]["final_metrics"]["avg_mse"],
    )
    print(f"  Using best method: {best_method}")

    config = create_federated_experiment_config(
        num_clients=4,
        samples_per_client=200,
        rounds=15,
        local_epochs=5,
        aggregation=best_method,
    )

    with tempfile.TemporaryDirectory() as temp_dir:
        datasets = generate_fl_datasets(
            num_clients=4, samples_per_client=200, output_dir=temp_dir
        )

        # Analyze client data
        client_stats = []
        for i, paths in enumerate(datasets):
            df = pd.read_csv(paths["train"])

            # Calculate client statistics
            stats = {
                "client_id": i,
                "data_size": len(df),
                "target_mean": df["score"].mean(),
                "target_std": df["score"].std(),
                "feature_means": {
                    col: df[col].mean() for col in df.columns if col != "score"
                },
                "grade_distribution": df.get("grade", pd.Series(dtype="object"))
                .value_counts()
                .to_dict(),
            }
            client_stats.append(stats)

        # Run training
        history = federated_training(
            dataset_paths=datasets,
            rounds=15,
            local_epochs=5,
            aggregation=best_method,
            verbose=True,
        )

        # Create detailed plots
        create_beginner_friendly_convergence_plot(
            history, save_path=results_dir / "detailed_convergence_analysis.png"
        )

        create_client_diversity_dashboard(
            client_stats, save_path=results_dir / "client_diversity_dashboard.png"
        )

    # Save experiment summary
    experiment_summary = {
        "client_scaling_results": client_scaling_results,
        "aggregation_results": aggregation_results,
        "best_aggregation_method": best_method,
        "final_detailed_history": history,
        "client_statistics": client_stats,
    }

    with open(results_dir / "experiment_summary.json", "w") as f:
        json.dump(experiment_summary, f, indent=2, cls=NumpyEncoder)

    print("\n🎉 All experiments completed!")
    print(f"📁 Results saved to: {results_dir}")
    print(f"🏆 Best aggregation method: {best_method}")

    return experiment_summary


if __name__ == "__main__":
    print("🎨 Comprehensive Federated Learning Visualization Suite")
    print("=" * 50)

    choice = input(
        """
Choose what you'd like to do:
1. Run comprehensive FL experiments with enhanced plots

Enter choice (1): """
    )

    if choice == "1":
        run_comprehensive_fl_experiments()
    else:
        print("Running comprehensive experiments...")
        run_comprehensive_fl_experiments()
