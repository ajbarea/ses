import matplotlib.pyplot as plt
from pathlib import Path


def plot_results(results, x_key, x_label, plot_prefix, docs_dir):
    """
    Generalized plotting for both layer and neuron sweeps.
    - results: list of dicts with keys including x_key, mse, mae, train_time, eval_time, epoch_losses
    - x_key: 'layers' or 'neurons'
    - x_label: label for x axis
    - plot_prefix: 'layer' or 'neuron'
    - docs_dir: Path to output directory
    """
    x_vals = [r[x_key] for r in results]
    mse = [r["mse"] for r in results]
    mae = [r["mae"] for r in results]
    train_time = [r["train_time"] for r in results]
    eval_time = [r["eval_time"] for r in results]

    fig, axes = plt.subplots(2, 1, figsize=(6, 8))
    axes[0].plot(x_vals, mse, marker="o", label="MSE")
    axes[0].plot(x_vals, mae, marker="x", label="MAE")
    axes[0].set_xlabel(x_label)
    axes[0].set_ylabel("Error")
    axes[0].set_title(f"Model Error vs {x_label}")
    axes[0].legend()

    axes[1].plot(x_vals, train_time, marker="o", label="Train Time (s)")
    axes[1].plot(x_vals, eval_time, marker="x", label="Eval Time (s)")
    axes[1].set_xlabel(x_label)
    axes[1].set_ylabel("Time (s)")
    axes[1].set_title(f"Resource Usage vs {x_label}")
    axes[1].legend()

    fig.tight_layout()
    plot_path = docs_dir / f"{plot_prefix}_experiment.png"
    plt.savefig(plot_path)
    print(f"Plot saved to {plot_path}")

    # Training loss curves
    fig2, ax = plt.subplots(figsize=(8, 5))
    for r in results:
        ax.plot(
            range(1, len(r["epoch_losses"]) + 1),
            r["epoch_losses"],
            label=f"{r[x_key]} {x_label.lower()}",
        )
    ax.set_xlabel("Epoch")
    ax.set_ylabel("Training Loss")
    ax.set_title(f"Training Loss per Epoch for Different {x_label}")
    ax.legend()
    fig2.tight_layout()
    loss_plot = docs_dir / f"{plot_prefix}_training_curves.png"
    plt.savefig(loss_plot)
    print(f"Training curves saved to {loss_plot}")
