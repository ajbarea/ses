# SES - Security Evaluation System

[![codecov](https://codecov.io/gh/ajbarea/ses/graph/badge.svg?token=3PfdAPHO7K)](https://codecov.io/gh/ajbarea/ses) [![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=ajbarea_ses&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=ajbarea_ses)

A Windows security assessment tool that collects system metrics, evaluates them against security rules, and generates reports with findings and recommendations.

## Features

- **System Metrics Collection**: Patch status, open ports, services, firewall, antivirus, password policy
- **Dual Evaluation Engines**: Basic Python rules (always available) + CLIPS expert system (optional)
- **Security Scoring**: Numerical scores, grades, and detailed findings with recommendations
- **REST API**: FastAPI endpoints for integration
- **Machine Learning**: Train models to approximate expert system behavior
- **Federated Learning**: Privacy-preserving technique for collaboratively training machine learning models across multiple clients without sharing raw data

## Quick Start

### Backend Setup

```bash
cd backend
python -m venv .venv
source .venv/Scripts/activate  # Windows
python -m pip install --upgrade pip
pip install -r requirements.txt
uvicorn main:app --reload --reload-exclude logs/
```

### Frontend Setup

```bash
cd frontend
npm install
echo "NEXT_PUBLIC_API_URL=http://localhost:8000" > .env.local
npm run dev
```

## API Endpoints

- **GET /** - Health check
- **GET /metrics** - System security metrics
- **GET /evaluate** - Security evaluation results
- **Docs**: <http://localhost:8000/docs>

## Documentation

### Core System Documentation

- **[Security Evaluation System](backend/docs/security_evaluation.md)** - Metric collection, rule evaluation, and scoring
- **[Expert System Implementation](backend/docs/expert_system.md)** - CLIPS-based advanced evaluation
- **[System Configuration](backend/docs/system_configuration.md)** - Deployment, logging, and operations

### Advanced Features

- **[Machine Learning Pipeline](backend/docs/machine_learning_pipeline.md)** - Neural network training to approximate expert system
- **[Federated Learning Pipeline](backend/docs/federated_learning_pipeline.md)** - Privacy-preserving collaborative model training
- **[Synthetic Data Generation](backend/docs/data_generation.md)** - Generate training datasets
- **[System Architecture](backend/docs/models/ses_system_architecture.mermaid)** - Visual system overview

### Rule Systems

- **[CLIPS Rules Directory](backend/src/clips_rules/)** - Expert system rule files
  - [Patch Rules](backend/src/clips_rules/patch_rules.clp) - Windows update evaluation
  - [Port Rules](backend/src/clips_rules/port_rules.clp) - Network security assessment
  - [Firewall Rules](backend/src/clips_rules/firewall_rules.clp) - Firewall analysis
  - [Password Rules](backend/src/clips_rules/password_rules.clp) - Password policy validation
  - [Antivirus Rules](backend/src/clips_rules/antivirus_rules.clp) - Antivirus status checking

## Machine Learning Workflow

```bash
# Generate training data
cd backend
python -m src.data_generator -n 1000 --split 0.8 -o security_data_split.csv

# Train neural network
cd ml/experiments
python train_security_model.py
```

## Federated Learning Workflow

```bash
cd backend
python -m fl.experiments.fl_experiments
```

This command generates federated datasets and orchestrates collaborative training across simulated clients.

### Run Individual Federated Learning Experiments

- **Basic Convergence Test**  
  Evaluate if the federated model converges as expected:

  ```bash
  python -m fl.experiments.convergence_experiment
  ```

- **Aggregation Methods Comparison**  
  Compare different aggregation strategies (e.g., FedAvg, weighted, median, secure) for combining client updates:

  ```bash
  python -m fl.experiments.aggregation_experiment
  ```

- **Privacy Impact Analysis**  
  Assess the effect of privacy-preserving techniques (e.g., noise injection) on model performance:

  ```bash
  python -m fl.experiments.privacy_experiment
  ```

## Neural Network Experiments

The neural network module enables you to optimize and evaluate machine learning models that approximate the expert system’s security scoring.

### Overview

The `ml_experiments.py` script allows you to systematically analyze how different neural network architectures—specifically, the number of hidden layers and neurons per layer—affect model performance, training time, and resource usage. This helps you find the best trade-off between accuracy and efficiency for your use case.

### How to Run Experiments

1. **Generate Training Data**

   ```bash
   cd backend
   python -m src.data_generator -n 1000 --split 0.8 -o security_data_split.csv
   ```

2. **Run Architecture Experiments**

   ```bash
   cd ml/experiments
   python ml_experiments.py
   ```

   - You can set the experiment mode (`layer`, `neuron`, or `both`) at the top of `ml_experiments.py` to control which architecture sweeps to run.

### What to Expect

- The script prints progress and results for each configuration.
- Plots and logs are saved to the `docs/experiments/` directory.

**Example Output:**

```bash
[Layer Sweep] 1/2: Training with 1 hidden layer(s)
  Training settings:
    - Number of epochs: 100
    - Batch size: 16
    - Learning rate: 0.001
    - Neurons per hidden layer: 64
{'layers': 1, 'neurons': 64, 'train_time': 12.34, 'eval_time': 0.15, 'memory_mb': 45.2, 'mse': 0.082, 'mae': 0.198, ...}
...
Plot saved to .../layer_experiment.png
Training curves saved to .../layer_training_curves.png
```

### Generated Visualizations

- **`layer_experiment.png`**: Accuracy and resource usage vs. number of hidden layers
- **`layer_training_curves.png`**: Training loss curves for different layer counts
- **`neuron_experiment.png`**: Error and resource usage vs. neurons per layer
- **`neuron_training_curves.png`**: Training loss curves for different neuron counts

These experiments help you identify the optimal neural network configuration for your security evaluation needs. For more details, see [Machine Learning Pipeline Documentation](backend/docs/machine_learning_pipeline.md).

## Testing

```bash
cd backend
python -m unittest discover
```

## Build Distribution

```bash
# Backend
cd backend && pip install -r requirements.txt

# Frontend + Electron
cd frontend && npm install && npm run electron:build
```

Output: `frontend/dist_electron/` contains platform-specific installers.

## System Requirements

- **Windows**: Primary platform for security scanning
- **Python 3.11**: Backend runtime (Python 3.13 has PyTorch compatibility issues)
- **Node.js 22**: Frontend and Electron
- **Optional**: PyCLIPS for expert system features

---

_For detailed documentation, troubleshooting, and advanced configuration, see the [docs directory](backend/docs/)._
