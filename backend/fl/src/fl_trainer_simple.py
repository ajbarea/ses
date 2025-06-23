"""
Simple Federated Learning Implementation for SES

This module provides a simplified federated learning implementation using
the standard FedAvg (Federated Averaging) algorithm - the most basic and
widely-used FL technique.

Key simplifications:
- Only FedAvg aggregation (simple averaging)
- Minimal metrics tracking
- Streamlined training process
- No differential privacy or advanced features
- Focus on core FL concepts
"""

import tempfile
from pathlib import Path
from typing import Any, Dict, List

import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader

from ml.src.ml_trainer import SecurityDataset, SecurityNN, evaluate_security_model
from src.data_generator import generate_dataset, split_dataset, save_to_csv
from src.clips_evaluator import SecurityExpertSystem


def generate_simple_fl_datasets(
    num_clients: int = 3,
    samples_per_client: int = 150,
    output_dir: str = "",
) -> List[Dict[str, Path]]:
    """Generate simple federated datasets for each client.

    Args:
        num_clients: Number of federated clients (default: 3)
        samples_per_client: Dataset size per client (default: 150)
        output_dir: Directory to save datasets (default: temp directory)

    Returns:
        List of dictionaries with train/test paths for each client
    """
    expert_system = SecurityExpertSystem()
    output_path = Path(output_dir) if output_dir else Path(tempfile.mkdtemp())
    datasets = []

    print(
        f"Generating {num_clients} client datasets with {samples_per_client} samples each..."
    )

    for i in range(num_clients):
        # Each client gets slightly different data distribution
        bias = (
            0.3 + i * 0.1
        )  # Client 0: 30%, Client 1: 40%, Client 2: 50% excellent bias
        data = generate_dataset(expert_system, samples_per_client, bias)
        train, test = split_dataset(data, 0.8)  # 80% train, 20% test

        train_path = output_path / f"client_{i+1}_train.csv"
        test_path = output_path / f"client_{i+1}_test.csv"

        save_to_csv(train, train_path)
        save_to_csv(test, test_path)

        datasets.append({"train": train_path, "test": test_path})
        print(f"  Client {i+1}: {len(train)} train, {len(test)} test samples")

    return datasets


def train_local_model(model, data_loader, epochs: int = 3, device: torch.device = None):
    """Train a local model on client data (simplified version).

    Args:
        model: Neural network model to train
        data_loader: DataLoader with client's training data
        epochs: Number of local training epochs
        device: Device to train on (cuda/cpu)
    """
    if device is None:
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    model.train()
    optimizer = torch.optim.Adam(model.parameters(), lr=0.001)
    criterion = nn.MSELoss()

    for epoch in range(epochs):
        for batch in data_loader:
            optimizer.zero_grad()

            # Simple score prediction only (no grade classification)
            x, y_score = batch[0], batch[1]
            x, y_score = x.to(device), y_score.to(device)

            predictions = model(x)
            loss = criterion(predictions, y_score)

            loss.backward()
            optimizer.step()


def fedavg_aggregate(
    client_models: List[Dict[str, torch.Tensor]],
) -> Dict[str, torch.Tensor]:
    """FedAvg: Simple averaging of client model parameters.

    This is the core of federated learning - combining multiple client models
    into a single global model by averaging their parameters.

    Args:
        client_models: List of client model state dictionaries

    Returns:
        Averaged global model state dictionary
    """
    if not client_models:
        raise ValueError("No client models provided for aggregation")

    # Initialize global model with zeros
    global_model = {}

    # Average each parameter across all clients
    for param_name in client_models[0].keys():
        # Stack all client parameters for this layer
        stacked_params = torch.stack(
            [client_model[param_name].float() for client_model in client_models]
        )

        # Simple average
        global_model[param_name] = stacked_params.mean(dim=0)

    return global_model


def evaluate_simple_model(
    model, test_paths: List[Path], encoders, scaler
) -> Dict[str, float]:
    """Simple evaluation of the global model on all client test sets.

    Args:
        model: Trained global model
        test_paths: List of client test dataset paths
        encoders: Feature encoders from training
        scaler: Feature scaler from training

    Returns:
        Dictionary with average metrics across all clients
    """
    all_mse = []
    all_mae = []
    all_r2 = []

    for test_path in test_paths:
        try:
            # Create a minimal model data structure for evaluation
            model_data = {
                "model": model,
                "encoders": encoders,
                "scaler": scaler,
                "grade_encoder": None,  # Simplified - no grade prediction
                "dataset": None,
            }

            result = evaluate_security_model(model_data, str(test_path))
            all_mse.append(result["mse"])
            all_mae.append(result["mae"])
            all_r2.append(result["r2_score"])

        except Exception as e:
            print(f"Warning: Could not evaluate on {test_path}: {e}")
            continue

    return {
        "avg_mse": np.mean(all_mse) if all_mse else float("inf"),
        "avg_mae": np.mean(all_mae) if all_mae else float("inf"),
        "avg_r2": np.mean(all_r2) if all_r2 else 0.0,
        "num_clients_evaluated": len(all_mse),
    }


def simple_federated_training(
    dataset_paths: List[Dict[str, Path]],
    rounds: int = 5,
    local_epochs: int = 3,
    hidden_size: int = 64,
    batch_size: int = 16,
    verbose: bool = True,
) -> Dict[str, Any]:
    """Simple federated training using FedAvg algorithm.

    This implements the basic federated learning process:
    1. Initialize global model
    2. For each round:
       a. Send global model to all clients
       b. Each client trains locally
       c. Collect client models
       d. Average them (FedAvg)
       e. Evaluate global model

    Args:
        dataset_paths: List of client dataset paths
        rounds: Number of communication rounds
        local_epochs: Local training epochs per client
        hidden_size: Neural network hidden layer size
        batch_size: Training batch size
        verbose: Print progress information

    Returns:
        Dictionary with training history and final results
    """
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    if verbose:
        print("🚀 Starting Simple Federated Learning")
        print(f"📱 Device: {device}")
        print(f"👥 Clients: {len(dataset_paths)}")
        print(f"🔄 Rounds: {rounds}")
        print(f"📚 Local epochs: {local_epochs}")
        print("-" * 50)

    # Set up shared encoders using first client's data
    base_dataset = SecurityDataset(dataset_paths[0]["train"], fit_encoders=True)
    encoders = base_dataset.encoders
    scaler = base_dataset.scaler
    input_size = base_dataset.features.shape[1]

    # Create client data loaders
    clients = []
    for i, paths in enumerate(dataset_paths):
        train_ds = SecurityDataset(
            paths["train"],
            fit_encoders=False,
            encoders=encoders,
            scaler=scaler,
        )
        train_loader = DataLoader(train_ds, batch_size=batch_size, shuffle=True)
        clients.append(
            {
                "train_loader": train_loader,
                "test_path": paths["test"],
                "client_id": i + 1,
            }
        )

    # Initialize global model
    global_model = SecurityNN(input_size, hidden_size, hidden_layers=2).to(device)

    # Track training progress
    history = {
        "rounds": [],
        "global_mse": [],
        "global_mae": [],
        "global_r2": [],
    }

    # Federated training rounds
    for round_num in range(rounds):
        if verbose:
            print(f"\n📡 Round {round_num + 1}/{rounds}")

        # Store client models after local training
        client_models = []

        # Each client trains locally
        for client in clients:
            if verbose:
                print(f"  🏢 Training Client {client['client_id']}...")

            # Create local copy of global model
            local_model = SecurityNN(input_size, hidden_size, hidden_layers=2).to(
                device
            )
            local_model.load_state_dict(global_model.state_dict())

            # Local training
            train_local_model(local_model, client["train_loader"], local_epochs, device)

            # Store trained model parameters
            client_models.append(
                {k: v.cpu() for k, v in local_model.state_dict().items()}
            )

        # FedAvg: Average all client models
        if verbose:
            print("  ⚖️  Aggregating client models (FedAvg)...")

        global_params = fedavg_aggregate(client_models)
        global_model.load_state_dict(global_params)

        # Evaluate global model
        if verbose:
            print("  📊 Evaluating global model...")

        test_paths = [client["test_path"] for client in clients]
        metrics = evaluate_simple_model(global_model, test_paths, encoders, scaler)

        # Record metrics
        history["rounds"].append(round_num + 1)
        history["global_mse"].append(metrics["avg_mse"])
        history["global_mae"].append(metrics["avg_mae"])
        history["global_r2"].append(metrics["avg_r2"])

        if verbose:
            print(f"  📈 MSE: {metrics['avg_mse']:.4f}")
            print(f"  📈 MAE: {metrics['avg_mae']:.4f}")
            print(f"  📈 R²:  {metrics['avg_r2']:.4f}")

    # Final results
    final_metrics = {
        "final_mse": (
            history["global_mse"][-1] if history["global_mse"] else float("inf")
        ),
        "final_mae": (
            history["global_mae"][-1] if history["global_mae"] else float("inf")
        ),
        "final_r2": history["global_r2"][-1] if history["global_r2"] else 0.0,
        "total_rounds": rounds,
        "num_clients": len(clients),
    }

    if verbose:
        print("\n🎉 Federated Learning Complete!")
        print(f"🏆 Final MSE: {final_metrics['final_mse']:.4f}")
        print(f"🏆 Final R²:  {final_metrics['final_r2']:.4f}")

    return {
        "history": history,
        "final_metrics": final_metrics,
        "global_model": global_model,
        "encoders": encoders,
        "scaler": scaler,
    }


def run_simple_experiment(
    num_clients: int = 3,
    samples_per_client: int = 150,
    rounds: int = 5,
    local_epochs: int = 3,
    output_dir: str = "",
) -> Dict[str, Any]:
    """Run a complete simple federated learning experiment.

    Args:
        num_clients: Number of federated clients
        samples_per_client: Dataset size per client
        rounds: Number of FL communication rounds
        local_epochs: Local training epochs per round
        output_dir: Directory for datasets and results

    Returns:
        Complete experiment results
    """
    print("🔬 Simple Federated Learning Experiment")
    print("=" * 45)

    # Generate datasets
    print("\n📊 Generating federated datasets...")
    datasets = generate_simple_fl_datasets(
        num_clients=num_clients,
        samples_per_client=samples_per_client,
        output_dir=output_dir,
    )

    # Run federated training
    print("\n🚀 Running federated training...")
    results = simple_federated_training(
        dataset_paths=datasets,
        rounds=rounds,
        local_epochs=local_epochs,
    )

    # Add experiment config to results
    results["config"] = {
        "num_clients": num_clients,
        "samples_per_client": samples_per_client,
        "rounds": rounds,
        "local_epochs": local_epochs,
        "aggregation_method": "fedavg",
    }

    return results


if __name__ == "__main__":
    # Run a simple demo experiment
    print("🎯 Simple Federated Learning Demo")
    print("This demonstrates the basic FedAvg algorithm")
    print("-" * 40)

    # Small demo configuration
    results = run_simple_experiment(
        num_clients=3,
        samples_per_client=100,
        rounds=5,
        local_epochs=3,
    )

    print("\n📋 Experiment Summary:")
    print(f"✅ Clients: {results['config']['num_clients']}")
    print(
        f"✅ Total samples: {results['config']['num_clients'] * results['config']['samples_per_client']}"
    )
    print(f"✅ Communication rounds: {results['config']['rounds']}")
    print(f"✅ Final performance: MSE = {results['final_metrics']['final_mse']:.4f}")

    if results["final_metrics"]["final_mse"] < 100:  # Arbitrary threshold
        print("🎉 Training successful! Model learned to predict security scores.")
    else:
        print("⚠️  Training may need more rounds or different configuration.")
