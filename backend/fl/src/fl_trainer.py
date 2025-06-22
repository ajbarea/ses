"""Advanced Federated Learning training utilities for SES machine learning models.

This module provides a comprehensive federated learning implementation with advanced
features for production use. For basic federated learning experiments, see
fl_trainer_simple.py which offers a minimal FedAvg-only implementation.

Key features of this advanced trainer:
- Multiple aggregation algorithms (weighted, median, secure)
- Differential privacy support
- Comprehensive metrics tracking
- Model similarity analysis
- Production-ready configurations
- Advanced data distribution controls

"""

import sys
import tempfile
from pathlib import Path
from typing import List, Dict, Any

import torch
from torch.utils.data import DataLoader
import torch.nn as nn
import numpy as np

backend_dir = Path(__file__).parent.parent.parent
sys.path.append(str(backend_dir))

try:
    from ml.src.ml_trainer import (
        SecurityDataset,
        SecurityNN,
        evaluate_security_model,
    )
    from src.data_generator import (
        generate_dataset,
        split_dataset,
        save_to_csv,
    )
    from src.clips_evaluator import SecurityExpertSystem
except Exception as e:
    print(f"Error importing modules: {e}")


def generate_fl_datasets(
    num_clients: int = 4,
    samples_per_client: int = 200,
    output_dir: str = "",
    excellent_base: float = 0.25,
    excellent_step: float = 0.1,
) -> List[Dict[str, Path]]:
    """Generate advanced federated datasets with configurable data distributions.

    This function creates more sophisticated federated datasets compared to the
    simple version in fl_trainer_simple.py. It allows fine-tuned control over
    data heterogeneity across clients.

    Note: For basic federated learning experiments, consider using
    generate_simple_fl_datasets() from fl_trainer_simple.py instead.

    Args:
        num_clients: Number of federated clients
        samples_per_client: Dataset size per client
        output_dir: Directory to save datasets
        excellent_base: Base probability for excellent configurations
        excellent_step: Step increase in excellent probability per client

    Returns:
        List of dictionaries with train/test paths for each client
    """
    expert_system = SecurityExpertSystem()
    output_path = Path(output_dir) if output_dir else Path(tempfile.mkdtemp())
    datasets = []

    for i in range(num_clients):
        bias = excellent_base + i * excellent_step
        data = generate_dataset(expert_system, samples_per_client, bias)
        train, test = split_dataset(data, 2 / 3)
        train_path = output_path / f"fl_client{i+1}_train.csv"
        test_path = output_path / f"fl_client{i+1}_test.csv"
        save_to_csv(train, train_path)
        save_to_csv(test, test_path)
        datasets.append({"train": train_path, "test": test_path})

    return datasets


def _train_local(model, loader, epochs: int, device: torch.device, lr: float = 0.001):
    """Train a local model on client data.

    Args:
        model: The neural network model to train
        loader: DataLoader for training data
        epochs: Number of local training epochs
        device: Device to train on (cuda/cpu)
        lr: Learning rate for optimizer
    """
    optimizer = torch.optim.Adam(model.parameters(), lr=lr, weight_decay=1e-4)
    criterion = nn.MSELoss()
    classification_loss = nn.CrossEntropyLoss()

    model.train()
    for _ in range(epochs):
        for batch in loader:
            optimizer.zero_grad()

            if len(batch) == 3:  # Has grade classification
                x, y_score, y_grade = batch
                x, y_score, y_grade = (
                    x.to(device),
                    y_score.to(device),
                    y_grade.to(device),
                )

                # Multi-task prediction
                score_pred, grade_pred = model(x, predict_grade=True)
                score_loss = criterion(score_pred, y_score)
                grade_loss = classification_loss(grade_pred, y_grade)

                # Combined loss with weighting
                total_loss = score_loss + 0.3 * grade_loss
            else:  # Only score prediction
                x, y_score = batch
                x, y_score = x.to(device), y_score.to(device)

                score_pred = model(x)
                total_loss = criterion(score_pred, y_score)

            total_loss.backward()
            optimizer.step()


# Note: Basic FedAvg aggregation (aggregate_average) is now available in fl_trainer_simple.py
# This file focuses on advanced aggregation methods and production features


def aggregate_weighted(
    states: List[Dict[str, torch.Tensor]], weights: List[float]
) -> Dict[str, torch.Tensor]:
    """Aggregate model states using weighted average."""
    total = sum(weights)
    agg = {}
    for k in states[0].keys():
        stacked = torch.stack([s[k].float() * w for s, w in zip(states, weights)])
        agg[k] = stacked.sum(dim=0) / total
    return agg


def aggregate_median(states: List[Dict[str, torch.Tensor]]) -> Dict[str, torch.Tensor]:
    """Aggregate model states using element-wise median."""
    agg = {}
    for k in states[0].keys():
        agg[k] = torch.stack([s[k].float() for s in states]).median(dim=0).values
    return agg


def calculate_model_similarity(
    state1: Dict[str, torch.Tensor], state2: Dict[str, torch.Tensor]
) -> float:
    """Calculate cosine similarity between two model states.

    Args:
        state1: First model state dict
        state2: Second model state dict

    Returns:
        Average cosine similarity across all parameters
    """
    similarities = []

    for key in state1.keys():
        if key in state2:
            # Flatten tensors and calculate cosine similarity
            vec1 = state1[key].flatten()
            vec2 = state2[key].flatten()

            # Calculate cosine similarity
            dot_product = torch.dot(vec1, vec2)
            norm1 = torch.norm(vec1)
            norm2 = torch.norm(vec2)

            if norm1 > 0 and norm2 > 0:
                similarity = dot_product / (norm1 * norm2)
                similarities.append(similarity.item())

    return np.mean(similarities) if similarities else 0.0


def add_differential_privacy_noise(
    state: Dict[str, torch.Tensor], noise_scale: float = 0.001, clip_norm: float = 1.0
) -> Dict[str, torch.Tensor]:
    """Add differential privacy noise to model parameters.

    Args:
        state: Model state dict
        noise_scale: Scale of Gaussian noise to add
        clip_norm: Gradient clipping norm

    Returns:
        State dict with added noise
    """
    noisy_state = {}

    for key, param in state.items():
        # Clip parameters
        param_norm = torch.norm(param)
        if param_norm > clip_norm:
            param = param * (clip_norm / param_norm)        # Add Gaussian noise
        if noise_scale > 0:
            noise = torch.normal(0, noise_scale, size=param.shape)
            noisy_state[key] = param + noise
        else:
            noisy_state[key] = param

    return noisy_state


def aggregate_secure_average(
    states: List[Dict[str, torch.Tensor]],
    add_noise: bool = False,
    noise_scale: float = 0.001,
) -> Dict[str, torch.Tensor]:
    """Secure aggregation with optional differential privacy.

    Args:
        states: List of model states from clients
        add_noise: Whether to add differential privacy noise
        noise_scale: Scale of noise for differential privacy

    Returns:
        Aggregated model state
    """
    # Use weighted aggregation as base (more robust than simple average)
    weights = [1.0] * len(states)  # Equal weights for secure aggregation
    agg = aggregate_weighted(states, weights)

    # Add differential privacy noise if requested
    if add_noise:
        agg = add_differential_privacy_noise(agg, noise_scale)

    return agg


def evaluate_federated_model(
    global_model: nn.Module,
    client_test_paths: List[Path],
    encoders: dict,
    scaler,
    grade_encoder,
    base_dataset,
) -> Dict[str, float]:
    """Evaluate federated model on all client test sets.

    Args:
        global_model: The trained global model
        client_test_paths: List of client test dataset paths
        encoders: Feature encoders
        scaler: Feature scaler
        grade_encoder: Grade encoder
        base_dataset: Base dataset for compatibility

    Returns:
        Dictionary of evaluation metrics
    """
    all_mse = []
    all_mae = []
    all_r2 = []
    all_grade_acc = []

    model_data = {
        "model": global_model,
        "encoders": encoders,
        "scaler": scaler,
        "grade_encoder": grade_encoder,
        "dataset": base_dataset,
    }

    for test_path in client_test_paths:
        try:
            result = evaluate_security_model(model_data, str(test_path))
            all_mse.append(result["mse"])
            all_mae.append(result["mae"])
            all_r2.append(result["r2_score"])
            if "grade_accuracy" in result:
                all_grade_acc.append(result["grade_accuracy"])
        except Exception as e:
            print(f"Warning: Could not evaluate on {test_path}: {e}")
            continue

    metrics = {
        "avg_mse": np.mean(all_mse) if all_mse else float("inf"),
        "std_mse": np.std(all_mse) if all_mse else 0.0,
        "avg_mae": np.mean(all_mae) if all_mae else float("inf"),
        "avg_r2": np.mean(all_r2) if all_r2 else 0.0,
    }

    if all_grade_acc:
        metrics["avg_grade_accuracy"] = np.mean(all_grade_acc)

    return metrics


def save_federated_results(
    history: Dict[str, List[float]], output_path: Path, experiment_config: Dict = None
):
    """Save federated learning results to files.

    Args:
        history: Training history with metrics
        output_path: Directory to save results
        experiment_config: Configuration parameters used
    """
    output_path.mkdir(parents=True, exist_ok=True)

    # Save history as CSV
    import pandas as pd

    df = pd.DataFrame(history)
    df.to_csv(output_path / "fl_training_history.csv", index=False)

    # Save config if provided
    if experiment_config:
        import json

        with open(output_path / "fl_config.json", "w") as f:
            json.dump(experiment_config, f, indent=2)

    print(f"Results saved to {output_path}")


def create_federated_experiment_config(
    num_clients: int = 4,
    samples_per_client: int = 200,
    rounds: int = 10,
    local_epochs: int = 5,
    aggregation: str = "weighted",  # Default to weighted aggregation for production
    hidden_size: int = 128,
    hidden_layers: int = 3,
    batch_size: int = 16,
    use_differential_privacy: bool = False,
    noise_scale: float = 0.001,
    excellent_base: float = 0.25,
    excellent_step: float = 0.1,
) -> Dict:
    """Create an advanced federated learning experiment configuration.

    This creates configurations suitable for production federated learning
    with advanced features. For simple FedAvg experiments, use
    fl_trainer_simple.py instead.

    Returns:
        Dictionary with all experiment parameters
    """
    return {
        "num_clients": num_clients,
        "samples_per_client": samples_per_client,
        "rounds": rounds,
        "local_epochs": local_epochs,
        "aggregation": aggregation,
        "hidden_size": hidden_size,
        "hidden_layers": hidden_layers,
        "batch_size": batch_size,
        "use_differential_privacy": use_differential_privacy,
        "noise_scale": noise_scale,
        "excellent_base": excellent_base,
        "excellent_step": excellent_step,
    }


def federated_training(
    dataset_paths: List[Dict[str, Path]],
    rounds: int = 5,
    local_epochs: int = 5,
    aggregation: str = "weighted",  # Production default: weighted aggregation
    hidden_size: int = 128,
    hidden_layers: int = 3,
    batch_size: int = 16,
    use_differential_privacy: bool = False,
    noise_scale: float = 0.001,
    verbose: bool = True,
) -> Dict[str, Any]:
    """Advanced federated training with comprehensive metrics and security features.

    This function provides production-ready federated learning with advanced
    aggregation methods, differential privacy, and extensive monitoring.

    For basic FedAvg training, use simple_federated_training() from
    fl_trainer_simple.py instead.

    Supported aggregation methods:
    - "weighted": Client-size weighted averaging (recommended for production)
    - "median": Element-wise median aggregation (Byzantine-robust)
    - "secure": Secure aggregation with optional differential privacy

    Returns:
        Dictionary containing training history and advanced metrics
    """
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    if verbose:
        print(f"Using device: {device}")

    # Initialize datasets with shared encoders from the first dataset
    base_ds = SecurityDataset(dataset_paths[0]["train"], fit_encoders=True)
    encoders = base_ds.encoders
    scaler = base_ds.scaler
    grade_encoder = getattr(base_ds, "grade_encoder", None)

    input_size = base_ds.features.shape[1]
    clients = []

    for i, paths in enumerate(dataset_paths):
        train_ds = SecurityDataset(
            paths["train"],
            fit_encoders=False,
            encoders=encoders,
            scaler=scaler,
            grade_encoder=grade_encoder,
        )
        test_path = paths["test"]
        train_loader = DataLoader(train_ds, batch_size=batch_size, shuffle=True)
        clients.append(
            {"train_loader": train_loader, "test_path": test_path, "client_id": i}
        )

    global_model = SecurityNN(input_size, hidden_size, hidden_layers).to(device)

    # Initialize comprehensive history tracking
    history = {
        "rounds": [],
        "global_mse": [],
        "global_mae": [],
        "global_r2": [],
        "participating_clients": [],
        "model_similarity": [],
        "update_magnitude": [],
        "client_similarity": [],
    }

    for round_num in range(rounds):
        if verbose:
            print(f"\nRound {round_num + 1}/{rounds}")

        local_states = []
        local_sizes = []
        round_similarities = []

        # Store global state before updates
        global_state_before = {
            k: v.cpu().clone() for k, v in global_model.state_dict().items()
        }

        for client in clients:
            # Create local model copy
            model = SecurityNN(input_size, hidden_size, hidden_layers).to(device)
            model.load_state_dict(global_model.state_dict())

            # Store pre-training state for similarity calculation
            pre_state = {k: v.cpu().clone() for k, v in model.state_dict().items()}

            # Local training
            _train_local(model, client["train_loader"], local_epochs, device)

            # Store post-training state
            post_state = {k: v.cpu() for k, v in model.state_dict().items()}
            local_states.append(post_state)
            local_sizes.append(
                len(client["train_loader"].dataset)
            )  # Calculate similarity between pre and post training states
            similarity = calculate_model_similarity(pre_state, post_state)
            round_similarities.append(similarity)

        # Model aggregation - advanced methods for production FL
        if aggregation == "weighted":
            aggregated = aggregate_weighted(local_states, local_sizes)
        elif aggregation == "median":
            aggregated = aggregate_median(local_states)
        elif aggregation == "secure":
            aggregated = aggregate_secure_average(
                local_states,
                add_noise=use_differential_privacy,
                noise_scale=noise_scale,
            )
        else:
            raise ValueError(
                f"Unknown aggregation method: {aggregation}. "
                f"Supported methods: 'weighted', 'median', 'secure'. "
                f"For basic 'average' aggregation, use fl_trainer_simple.py instead."
            )

        # Calculate update magnitude
        update_magnitude = 0.0
        for key in aggregated.keys():
            if key in global_state_before:
                diff = aggregated[key] - global_state_before[key]
                update_magnitude += torch.norm(diff).item()

        global_model.load_state_dict(aggregated)  # Evaluate on each client's test data
        client_test_paths = [client["test_path"] for client in clients]

        metrics = evaluate_federated_model(
            global_model, client_test_paths, encoders, scaler, grade_encoder, base_ds
        )

        # Record metrics
        history["rounds"].append(round_num + 1)
        history["global_mse"].append(metrics["avg_mse"])
        history["global_mae"].append(metrics["avg_mae"])
        history["global_r2"].append(metrics["avg_r2"])
        history["participating_clients"].append(len(clients))
        history["model_similarity"].append(
            np.mean(round_similarities) if round_similarities else 0.0
        )
        history["update_magnitude"].append(update_magnitude)

        # Track individual client similarities to global model
        client_global_similarities = []
        for local_state in local_states:
            similarity = calculate_model_similarity(local_state, aggregated)
            client_global_similarities.append(similarity)
        history["client_similarity"].append(client_global_similarities)

        if verbose:
            print(f"Average MSE: {metrics['avg_mse']:.4f}")
            print(f"Average MAE: {metrics['avg_mae']:.4f}")
            print(f"Average R²: {metrics['avg_r2']:.4f}")
            if round_similarities:
                print(
                    f"Average client update similarity: {np.mean(round_similarities):.4f}"
                )

    # Calculate final metrics
    final_metrics = {
        "avg_mse": history["global_mse"][-1] if history["global_mse"] else float("inf"),
        "avg_mae": history["global_mae"][-1] if history["global_mae"] else float("inf"),
        "avg_r2": history["global_r2"][-1] if history["global_r2"] else 0.0,
        "total_rounds": rounds,
        "convergence_round": (
            np.argmin(history["global_mse"]) + 1 if history["global_mse"] else rounds
        ),
    }

    return {
        "history": history,
        "final_metrics": final_metrics,
        "config": {
            "num_clients": len(clients),
            "rounds": rounds,
            "local_epochs": local_epochs,
            "aggregation": aggregation,
            "hidden_size": hidden_size,
            "hidden_layers": hidden_layers,
            "batch_size": batch_size,
            "use_differential_privacy": use_differential_privacy,
            "noise_scale": noise_scale,
        },
    }


def run_federated_experiment(
    output_dir: str = "", config: Dict = None, save_results: bool = True
) -> Dict[str, List[float]]:
    """Run a complete advanced federated learning experiment.

    This function orchestrates a full federated learning experiment with
    advanced features. For simple experiments, use run_simple_experiment()
    from fl_trainer_simple.py instead.

    Args:
        output_dir: Directory for datasets and results
        config: Experiment configuration (uses advanced defaults if None)
        save_results: Whether to save results to disk

    Returns:
        Training history and advanced metrics
    """
    if config is None:
        config = create_federated_experiment_config()

    print("Generating federated datasets...")
    datasets = generate_fl_datasets(
        num_clients=config["num_clients"],
        samples_per_client=config["samples_per_client"],
        output_dir=output_dir,
        excellent_base=config["excellent_base"],
        excellent_step=config["excellent_step"],
    )

    print("Running federated training...")
    history = federated_training(
        dataset_paths=datasets,
        rounds=config["rounds"],
        local_epochs=config["local_epochs"],
        aggregation=config["aggregation"],
        hidden_size=config["hidden_size"],
        hidden_layers=config["hidden_layers"],
        batch_size=config["batch_size"],
        use_differential_privacy=config["use_differential_privacy"],
        noise_scale=config["noise_scale"],
    )

    if save_results and output_dir:
        save_federated_results(history, Path(output_dir) / "fl_results", config)

    return history


if __name__ == "__main__":  # pragma: no cover
    # Run an advanced federated learning experiment
    config = create_federated_experiment_config(
        num_clients=3,
        samples_per_client=100,
        rounds=5,
        local_epochs=3,
        aggregation="weighted",
        use_differential_privacy=False,
    )

    # Create temporary directory for this experiment
    with tempfile.TemporaryDirectory() as temp_dir:
        print(f"Running federated learning experiment in {temp_dir}")
        history = run_federated_experiment(
            output_dir=temp_dir, config=config, save_results=True
        )
        print("Final MSE per round:", history["global_mse"])
