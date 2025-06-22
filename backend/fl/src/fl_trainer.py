"""Federated learning training utilities for SES machine learning models."""

from pathlib import Path
from typing import List, Dict

import torch
from torch.utils.data import DataLoader
import torch.nn as nn

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


def generate_fl_datasets(
    num_clients: int = 4,
    samples_per_client: int = 200,
    output_dir: str = "",
    excellent_base: float = 0.25,
    excellent_step: float = 0.1,
) -> List[Dict[str, Path]]:
    """Generate datasets for each federated client.

    Each dataset uses the same expert system but with varying bias toward
    excellent configurations.
    """
    expert_system = SecurityExpertSystem()
    output_path = Path(output_dir)
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
    optimizer = torch.optim.Adam(model.parameters(), lr=lr, weight_decay=1e-4)
    criterion = nn.MSELoss()
    model.train()
    for _ in range(epochs):
        for batch in loader:
            if len(batch) == 3:
                x, y, _ = batch
            else:
                x, y = batch
            x, y = x.to(device), y.to(device)
            optimizer.zero_grad()
            preds = model(x)
            loss = criterion(preds, y)
            loss.backward()
            optimizer.step()


def aggregate_average(states: List[Dict[str, torch.Tensor]]) -> Dict[str, torch.Tensor]:
    """Aggregate model states using element-wise average."""
    agg = {}
    for k in states[0].keys():
        agg[k] = torch.stack([s[k].float() for s in states]).mean(dim=0)
    return agg


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


def federated_training(
    dataset_paths: List[Dict[str, Path]],
    rounds: int = 5,
    local_epochs: int = 5,
    aggregation: str = "average",
    hidden_size: int = 128,
    hidden_layers: int = 3,
    batch_size: int = 16,
) -> Dict[str, List[float]]:
    """Run a simple federated learning experiment.

    Returns a dictionary with recorded global MSE after each round.
    """
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    # Initialize datasets with shared encoders from the first dataset
    base_ds = SecurityDataset(dataset_paths[0]["train"], fit_encoders=True)
    encoders = base_ds.encoders
    scaler = base_ds.scaler
    grade_encoder = getattr(base_ds, "grade_encoder", None)

    input_size = base_ds.features.shape[1]
    clients = []

    for paths in dataset_paths:
        train_ds = SecurityDataset(
            paths["train"],
            fit_encoders=False,
            encoders=encoders,
            scaler=scaler,
            grade_encoder=grade_encoder,
        )
        test_path = paths["test"]
        test_ds = SecurityDataset(
            test_path,
            fit_encoders=False,
            encoders=encoders,
            scaler=scaler,
            grade_encoder=grade_encoder,
        )
        train_loader = DataLoader(train_ds, batch_size=batch_size, shuffle=True)
        clients.append({"train_loader": train_loader, "test_path": test_path})

    global_model = SecurityNN(input_size, hidden_size, hidden_layers).to(device)
    history = {"global_mse": []}

    for _ in range(rounds):
        local_states = []
        local_sizes = []
        for client in clients:
            model = SecurityNN(input_size, hidden_size, hidden_layers).to(device)
            model.load_state_dict(global_model.state_dict())
            _train_local(model, client["train_loader"], local_epochs, device)
            local_states.append({k: v.cpu() for k, v in model.state_dict().items()})
            local_sizes.append(len(client["train_loader"].dataset))

        if aggregation == "average":
            aggregated = aggregate_average(local_states)
        elif aggregation == "weighted":
            aggregated = aggregate_weighted(local_states, local_sizes)
        elif aggregation == "median":
            aggregated = aggregate_median(local_states)
        else:
            raise ValueError(f"Unknown aggregation method: {aggregation}")

        global_model.load_state_dict(aggregated)

        # Evaluate on each client's test data and record average MSE
        mses = []
        for client in clients:
            data = {
                "model": global_model,
                "encoders": encoders,
                "scaler": scaler,
                "grade_encoder": grade_encoder,
                "dataset": base_ds,
            }
            result = evaluate_security_model(data, str(client["test_path"]))
            mses.append(result["mse"])
        history["global_mse"].append(sum(mses) / len(mses))

    return history


if __name__ == "__main__":  # pragma: no cover
    datasets = generate_fl_datasets()
    stats = federated_training(datasets)
    print("Global MSE per round:", stats["global_mse"])
