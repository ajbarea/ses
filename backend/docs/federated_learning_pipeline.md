# Federated Learning Pipeline Documentation

This document provides an up-to-date overview of the federated learning (FL) implementation in the Security Evaluation System (SES). The FL pipeline enables collaborative machine learning across multiple organizations while preserving data privacy and security.

## Implementation Overview

SES provides two federated learning implementations:

### 1. Simple Implementation: `fl_trainer_simple.py`

- **Purpose**: Learn FL basics, quick demos, proof-of-concept
- **Algorithm**: FedAvg (simple averaging)
- **Features**: Minimal code, fast execution, no privacy features
- **Location**: `backend/fl/src/fl_trainer_simple.py`

### 2. Advanced Implementation: `fl_trainer.py`

- **Purpose**: Research, advanced experiments, production
- **Algorithms**: Weighted, Median, Secure (with optional differential privacy)
- **Features**: Differential privacy, comprehensive metrics, model similarity, robust aggregation
- **Location**: `backend/fl/src/fl_trainer.py`

Both enable distributed neural network training across clients, sharing only model parameters (not raw data).

## Running Federated Learning Experiments

### Quick Start

#### Comprehensive Experiments (Recommended)

```bash
cd backend/fl/experiments
python fl_experiments.py
# Choose option 1 for comprehensive experiments
```

#### Quick Demo (Simple FedAvg)

```bash
cd backend/fl/src
python fl_trainer_simple.py
```

#### Individual Experiments

```bash
# Convergence
python -m fl.experiments.convergence_experiment
# Aggregation methods
python -m fl.experiments.aggregation_experiment
# Privacy impact
python -m fl.experiments.privacy_experiment
```

### What You Learn

- **Convergence**: How FL models improve over rounds
- **Client Diversity**: Impact of different data distributions
- **Aggregation Comparison**: FedAvg, Weighted, Median, Secure
- **Privacy-Utility Tradeoff**: Differential privacy effects
- **Communication Efficiency**: Local vs global training balance

### Output Plots

Results are saved in `backend/fl/experiments/results/`:

- `convergence_plot.png`: Model convergence
- `client_diversity.png`: Data distribution
- `aggregation_methods_comparison.png`: Aggregation strategies
- `privacy_impact.png`: Privacy-utility tradeoff

## Federated Learning Concepts

- **Federated Learning**: Clients train locally, share only model updates, not raw data
- **Data Heterogeneity**: Each client can have different data distributions (IID vs non-IID)
- **Aggregation Methods**:
  - **FedAvg**: Simple average (all clients equal)
  - **Weighted**: Larger datasets get more influence
  - **Median**: Robust to outliers
  - **Secure**: Adds noise for privacy (differential privacy)
- **Differential Privacy**: Adds noise to updates to protect individual data
- **Model Similarity**: Tracks convergence and detects anomalies

## Dataset Generation

Datasets are generated to simulate real-world client diversity:

```python
from fl.src.fl_trainer import generate_fl_datasets
client_datasets = generate_fl_datasets(num_clients=4, samples_per_client=200)
```

- Each client gets a different bias toward excellent security configurations (see `excellent_base` and `excellent_step` in code).
- Uses the CLIPS-based `SecurityExpertSystem` for ground truth labels.

## Advanced Training Example

```python
from fl.src.fl_trainer import federated_training, generate_fl_datasets

datasets = generate_fl_datasets(num_clients=4, samples_per_client=200)
results = federated_training(
    dataset_paths=datasets,
    aggregation="weighted",  # or "median", "secure"
    use_differential_privacy=True,  # optional
    noise_scale=0.001,  # privacy noise level
)
```

## Aggregation Methods in Detail

- **FedAvg**: Simple average of all client model parameters
- **Weighted**: Average weighted by client dataset size
- **Median**: Element-wise median, robust to outliers
- **Secure**: Adds noise for privacy (differential privacy)

## Privacy and Security Features

- **Differential Privacy**: Optional, adds Gaussian noise to updates
- **Gradient Clipping**: Bounds parameter magnitudes
- **Privacy Budget**: Controls privacy-utility tradeoff
- **Model Similarity**: Cosine similarity to monitor convergence and detect attacks

## Performance Evaluation

- **Global MSE**: Overall error
- **Per-Client MSE**: Individual client performance
- **Average Local MSE**: Mean across clients
- **Performance Variance**: Fairness
- **Communication Efficiency**: Bandwidth and convergence speed
- **Privacy Metrics**: Privacy budget, data leakage risk

## Integration with Security Evaluation

- Datasets and models are fully compatible with the SES security evaluation pipeline.
- Trained federated models can be saved and loaded for deployment:

```python
# Save model
import torch
torch.save(global_model.state_dict(), "models/federated_security_model.pth")
# Load model
model = SecurityNN(input_size=feature_count, hidden_size=128, output_size=1)
model.load_state_dict(torch.load("models/federated_security_model.pth"))
```

## Command Line Reference

- **Comprehensive FL**: `python -m fl.experiments.fl_experiments`
- **Simple FL**: `python fl_trainer_simple.py`
- **Aggregation**: `python -m fl.experiments.aggregation_experiment`
- **Privacy**: `python -m fl.experiments.privacy_experiment`

## Codebase Accuracy

- All experiment scripts, aggregation methods, and privacy features described here are implemented and tested in the codebase.
- The documentation reflects the current state of the SES federated learning pipeline as of June 2025.
