import time
import tracemalloc
from pathlib import Path
from backend.ml.src.ml_trainer import train_model, evaluate_security_model
from typing import Any, Dict
from backend.ml.experiments.ml_plotting import plot_results

try:
    from tqdm import tqdm

    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False

# --- Configuration ---
# Choose experiment mode: 'layer', 'neuron', or 'both'
EXPERIMENT_MODE = "layer"  # options: 'layer', 'neuron', 'both'

# Layer sweep settings
# LAYERS_TO_TEST = [1, 2, 4, 8, 16]
LAYERS_TO_TEST = [1, 2]
NEURONS_PER_LAYER = 64

# Neuron sweep settings
NEURONS_TO_TEST = [32, 64, 128, 256]
HIDDEN_LAYERS_COUNT = 2

TRAINING_EPOCHS = 100


def print_sweep(
    sweep_name: str,
    idx: int,
    total: int,
    main_param_name: str,
    main_param_value: Any,
    *,
    epochs: int,
    secondary_params: Dict[str, Any],
    batch_size: int = 16,
    lr: float = 0.001,
):
    print(
        f"\n[{sweep_name}] {idx+1}/{total}: Training with {main_param_value} {main_param_name}"
    )
    # Friendly names for parameters
    friendly = {
        "epochs": "Number of epochs (full passes through data)",
        "batch_size": "Batch size (samples per update)",
        "lr": "Learning rate (step size)",
        "neurons/layer": "Neurons per hidden layer",
        "layers": "Number of hidden layers",
    }
    params = {
        "epochs": epochs,
        "batch_size": batch_size,
        "lr": lr,
        **secondary_params,
    }
    print("  Training settings:")
    for k, v in params.items():
        label = friendly.get(k, k.replace("_", " ").capitalize())
        print(f"    - {label}: {v}")


def run_layer_experiment(layers_to_test, neurons_per_layer):
    results = []
    train_csv = Path(__file__).parent / "security_data_split_train.csv"
    test_csv = Path(__file__).parent / "security_data_split_test.csv"
    iterator = (
        tqdm(layers_to_test, desc="Layer Sweep") if TQDM_AVAILABLE else layers_to_test
    )
    for idx, layers in enumerate(iterator):
        print_sweep(
            sweep_name="Layer Sweep",
            idx=idx,
            total=len(layers_to_test),
            main_param_name="hidden layer(s)",
            main_param_value=layers,
            epochs=TRAINING_EPOCHS,
            secondary_params={"neurons/layer": neurons_per_layer},
        )
        tracemalloc.start()
        start_train = time.time()
        model_data = train_model(
            str(train_csv),
            model_type="security",
            target_col="target_score",
            epochs=TRAINING_EPOCHS,
            hidden_size=neurons_per_layer,
            hidden_layers=layers,
            lr=0.001,
            batch_size=16,
            progress_bar=True,
        )
        train_time = time.time() - start_train
        epoch_losses = model_data.get("losses", [])
        start_eval = time.time()
        eval_res = evaluate_security_model(model_data, str(test_csv))
        eval_time = time.time() - start_eval
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        results.append(
            {
                "layers": layers,
                "neurons": neurons_per_layer,
                "train_time": train_time,
                "eval_time": eval_time,
                "memory_mb": peak / (1024 * 1024),
                "mse": eval_res["mse"],
                "mae": eval_res["mae"],
                "epoch_losses": epoch_losses,
            }
        )
    return results


def run_neuron_experiment(neurons_to_test, hidden_layers_count):
    results = []
    train_csv = Path(__file__).parent / "security_data_split_train.csv"
    test_csv = Path(__file__).parent / "security_data_split_test.csv"
    iterator = (
        tqdm(neurons_to_test, desc="Neuron Sweep")
        if TQDM_AVAILABLE
        else neurons_to_test
    )
    for idx, neurons in enumerate(iterator):
        print_sweep(
            sweep_name="Neuron Sweep",
            idx=idx,
            total=len(neurons_to_test),
            main_param_name="neurons per layer",
            main_param_value=neurons,
            epochs=TRAINING_EPOCHS,
            secondary_params={"layers": hidden_layers_count},
        )
        tracemalloc.start()
        start_train = time.time()
        model_data = train_model(
            str(train_csv),
            model_type="security",
            target_col="target_score",
            epochs=TRAINING_EPOCHS,
            hidden_size=neurons,
            hidden_layers=hidden_layers_count,
            lr=0.001,
            batch_size=16,
            progress_bar=True,
        )
        train_time = time.time() - start_train
        epoch_losses = model_data.get("losses", [])
        start_eval = time.time()
        eval_res = evaluate_security_model(model_data, str(test_csv))
        eval_time = time.time() - start_eval
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        results.append(
            {
                "neurons": neurons,
                "layers": hidden_layers_count,
                "train_time": train_time,
                "eval_time": eval_time,
                "memory_mb": peak / (1024 * 1024),
                "mse": eval_res["mse"],
                "mae": eval_res["mae"],
                "epoch_losses": epoch_losses,
            }
        )
    return results


def main():
    docs_dir = Path(__file__).parent / "plots"
    docs_dir.mkdir(parents=True, exist_ok=True)

    if EXPERIMENT_MODE == "layer":
        results = run_layer_experiment(LAYERS_TO_TEST, NEURONS_PER_LAYER)
        for res in results:
            print(res)
        plot_results(
            results,
            x_key="layers",
            x_label="Hidden Layers",
            plot_prefix="layer",
            docs_dir=docs_dir,
        )
    elif EXPERIMENT_MODE == "neuron":
        results = run_neuron_experiment(NEURONS_TO_TEST, HIDDEN_LAYERS_COUNT)
        for res in results:
            print(res)
        plot_results(
            results,
            x_key="neurons",
            x_label="Neurons per Layer",
            plot_prefix="neuron",
            docs_dir=docs_dir,
        )
    elif EXPERIMENT_MODE == "both":
        print("Running both layer and neuron sweeps...")
        results_layer = run_layer_experiment(LAYERS_TO_TEST, NEURONS_PER_LAYER)
        for res in results_layer:
            print(res)
        plot_results(
            results_layer,
            x_key="layers",
            x_label="Hidden Layers",
            plot_prefix="layer",
            docs_dir=docs_dir,
        )
        results_neuron = run_neuron_experiment(NEURONS_TO_TEST, HIDDEN_LAYERS_COUNT)
        for res in results_neuron:
            print(res)
        plot_results(
            results_neuron,
            x_key="neurons",
            x_label="Neurons per Layer",
            plot_prefix="neuron",
            docs_dir=docs_dir,
        )
    else:
        print(f"Unknown EXPERIMENT_MODE: {EXPERIMENT_MODE}")


if __name__ == "__main__":
    main()
