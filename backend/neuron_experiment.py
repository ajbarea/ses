import time
import tracemalloc
from pathlib import Path
import matplotlib.pyplot as plt
import torch
import torch.nn as nn
from torch.utils.data import DataLoader

from src.ml_trainer import train_model, evaluate_security_model
from src.ml_trainer import SecurityDataset, SecurityNN, _train_security_model


TRAINING_EPOCHS = 100
DEFAULT_NEURONS_PER_LAYER = 64
HIDDEN_LAYERS_COUNT = 2


def run_experiment(neuron_counts):
    results = []
    train_csv = Path(__file__).parent / "security_data_split_train.csv"
    test_csv = Path(__file__).parent / "security_data_split_test.csv"

    for neurons in neuron_counts:
        print(f"\nTraining with {neurons} neurons per layer")
        start_train = time.time()
        model_data = train_model(
            str(train_csv),
            model_type="security",
            target_col="target_score",
            epochs=TRAINING_EPOCHS,
            hidden_size=neurons,
            hidden_layers=HIDDEN_LAYERS_COUNT,
            lr=0.001,
            batch_size=16,
            no_cuda=True,
        )
        train_time = time.time() - start_train

        # capture detailed training loss per epoch
        dataset = SecurityDataset(str(train_csv), target_col="target_score")
        loader = DataLoader(dataset, batch_size=16, shuffle=True)
        model = SecurityNN(
            input_size=dataset.features.shape[1],
            hidden_size=neurons,
            hidden_layers=HIDDEN_LAYERS_COUNT,
        )
        criterion = nn.MSELoss()
        classification_loss = nn.CrossEntropyLoss()
        optimizer = torch.optim.Adam(model.parameters(), lr=0.001)
        epoch_losses = _train_security_model(
            model,
            loader,
            criterion,
            optimizer,
            epochs=TRAINING_EPOCHS,
            device=torch.device("cpu"),
            classification_loss=classification_loss,
        )

        tracemalloc.start()
        start_eval = time.time()
        eval_res = evaluate_security_model(model_data, str(test_csv))
        eval_time = time.time() - start_eval
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        results.append(
            {
                "neurons": neurons,
                "train_time": train_time,
                "eval_time": eval_time,
                "memory_mb": peak / (1024 * 1024),
                "mse": eval_res["mse"],
                "mae": eval_res["mae"],
                "epoch_losses": epoch_losses,
            }
        )

    return results


def plot_results(results, path: Path):
    neurons = [r["neurons"] for r in results]
    mse = [r["mse"] for r in results]
    mae = [r["mae"] for r in results]
    train_time = [r["train_time"] for r in results]
    eval_time = [r["eval_time"] for r in results]

    fig, axes = plt.subplots(2, 1, figsize=(6, 8))

    axes[0].plot(neurons, mse, marker="o", label="MSE")
    axes[0].plot(neurons, mae, marker="x", label="MAE")
    axes[0].set_xlabel("Neurons per Layer")
    axes[0].set_ylabel("Error")
    axes[0].set_title("Model Error vs Neurons per Layer")
    axes[0].legend()

    axes[1].plot(neurons, train_time, marker="o", label="Train Time (s)")
    axes[1].plot(neurons, eval_time, marker="x", label="Eval Time (s)")
    axes[1].set_xlabel("Neurons per Layer")
    axes[1].set_ylabel("Time (s)")
    axes[1].set_title("Resource Usage vs Neurons per Layer")
    axes[1].legend()

    fig.tight_layout()
    plt.savefig(path)
    print(f"Plot saved to {path}")
    # plot training loss curves over epochs
    fig2, ax = plt.subplots(figsize=(8, 5))
    for r in results:
        ax.plot(
            range(1, len(r["epoch_losses"]) + 1),
            r["epoch_losses"],
            label=f"{r['neurons']} neurons",
        )
    ax.set_xlabel("Epoch")
    ax.set_ylabel("Training Loss")
    ax.set_title("Training Loss per Epoch for Different Neuron Counts")
    ax.legend()
    fig2.tight_layout()
    loss_plot = path.parent / "neuron_training_curves.png"
    plt.savefig(loss_plot)
    print(f"Training curves saved to {loss_plot}")


if __name__ == "__main__":
    neurons_to_test = [32, 64, 128, 256]
    results = run_experiment(neurons_to_test)
    for res in results:
        print(res)

    plot_path = Path(__file__).parent / "neuron_experiment.png"
    plot_results(results, plot_path)
