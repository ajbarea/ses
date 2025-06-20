import time
import tracemalloc
from pathlib import Path
import matplotlib.pyplot as plt

from src.ml_trainer import train_model, evaluate_security_model


TRAINING_EPOCHS = 100
NEURONS_PER_LAYER = 64


def run_experiment(layer_counts):
    results = []
    train_csv = Path(__file__).parent / "security_data_split_train.csv"
    test_csv = Path(__file__).parent / "security_data_split_test.csv"

    for layers in layer_counts:
        print(f"\nTraining with {layers} hidden layer(s)")
        start_train = time.time()
        model_data = train_model(
            str(train_csv),
            model_type="security",
            target_col="target_score",
            epochs=TRAINING_EPOCHS,
            hidden_size=NEURONS_PER_LAYER,
            hidden_layers=layers,
            lr=0.001,
            batch_size=16,
            no_cuda=True,
        )
        train_time = time.time() - start_train

        tracemalloc.start()
        start_eval = time.time()
        eval_res = evaluate_security_model(model_data, str(test_csv))
        eval_time = time.time() - start_eval
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        results.append(
            {
                "layers": layers,
                "train_time": train_time,
                "eval_time": eval_time,
                "memory_mb": peak / (1024 * 1024),
                "mse": eval_res["mse"],
                "mae": eval_res["mae"],
            }
        )

    return results


def plot_results(results, path: Path):
    layers = [r["layers"] for r in results]
    mse = [r["mse"] for r in results]
    mae = [r["mae"] for r in results]
    train_time = [r["train_time"] for r in results]
    eval_time = [r["eval_time"] for r in results]

    fig, axes = plt.subplots(2, 1, figsize=(6, 8))

    axes[0].plot(layers, mse, marker="o", label="MSE")
    axes[0].plot(layers, mae, marker="x", label="MAE")
    axes[0].set_xlabel("Hidden Layers")
    axes[0].set_ylabel("Error")
    axes[0].set_title("Model Error vs Hidden Layers")
    axes[0].legend()

    axes[1].plot(layers, train_time, marker="o", label="Train Time (s)")
    axes[1].plot(layers, eval_time, marker="x", label="Eval Time (s)")
    axes[1].set_xlabel("Hidden Layers")
    axes[1].set_ylabel("Time (s)")
    axes[1].set_title("Resource Usage vs Hidden Layers")
    axes[1].legend()

    fig.tight_layout()
    plt.savefig(path)
    print(f"Plot saved to {path}")


if __name__ == "__main__":
    layers_to_test = [1, 2, 4, 8, 16]
    results = run_experiment(layers_to_test)
    for res in results:
        print(res)

    plot_path = Path(__file__).parent / "layer_experiment.png"
    plot_results(results, plot_path)
