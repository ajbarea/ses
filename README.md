# SES - Security Evaluation System

[![codecov](https://codecov.io/gh/ajbarea/ses/graph/badge.svg?token=3PfdAPHO7K)](https://codecov.io/gh/ajbarea/ses) [![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=ajbarea_ses&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=ajbarea_ses)

A Windows security assessment tool that collects system metrics, evaluates them against security rules, and generates reports with findings and recommendations.

## Features

- **System Metrics Collection**: Patch status, open ports, services, firewall, antivirus, password policy
- **Dual Evaluation Engines**: Basic Python rules (always available) + CLIPS expert system (optional)
- **Security Scoring**: Numerical scores, grades, and detailed findings with recommendations
- **REST API**: FastAPI endpoints for integration
- **Machine Learning**: Train models to approximate expert system behavior

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

- **[Machine Learning Pipeline](backend/docs/ml_trainer.md)** - Neural network training to approximate expert system
- **[Synthetic Data Generation](backend/docs/data_generation.md)** - Generate training datasets
- **[System Architecture](backend/docs/models/ses_system_architecture.mermaid)** - Visual system overview

### Rule Systems

- **[CLIPS Rules Directory](backend/clips_rules/)** - Expert system rule files
  - [Patch Rules](backend/clips_rules/patch_rules.clp) - Windows update evaluation
  - [Port Rules](backend/clips_rules/port_rules.clp) - Network security assessment
  - [Firewall Rules](backend/clips_rules/firewall_rules.clp) - Firewall analysis
  - [Password Rules](backend/clips_rules/password_rules.clp) - Password policy validation
  - [Antivirus Rules](backend/clips_rules/antivirus_rules.clp) - Antivirus status checking

## Machine Learning Workflow

```bash
# Generate training data
cd backend
python -m src.data_generator -n 1000 --split 0.8 -o security_data_split.csv

# Train neural network
python train_security_model.py

# Expected output: R² > 0.95, Classification Accuracy > 90%
```

## Neural Network Layer Experiment

The `layer_experiment.py` script analyzes how different numbers of hidden layers affect model performance, training time, and resource usage. This experiment helps optimize the neural network architecture for the security evaluation model.

### Running the Experiment

```bash
# Generate training data
cd backend
python -m src.data_generator -n 1000 --split 0.8 -o security_data_split.csv

# Run hidden layer experiment
python layer_experiment.py
```

### Expected Terminal Output

The script tests models with 1, 2, 4, 8, and 16 hidden layers and produces output similar to:

```text
Training with 1 hidden layer(s)
Training with 2 hidden layer(s)
Training with 4 hidden layer(s)
Training with 8 hidden layer(s)
Training with 16 hidden layer(s)

{'layers': 1, 'train_time': 12.34, 'eval_time': 0.15, 'memory_mb': 45.2, 'mse': 0.082, 'mae': 0.198}
{'layers': 2, 'train_time': 15.67, 'eval_time': 0.18, 'memory_mb': 52.8, 'mse': 0.076, 'mae': 0.185}
{'layers': 4, 'train_time': 23.45, 'eval_time': 0.22, 'memory_mb': 68.1, 'mse': 0.071, 'mae': 0.179}
{'layers': 8, 'train_time': 38.92, 'eval_time': 0.31, 'memory_mb': 94.7, 'mse': 0.069, 'mae': 0.175}
{'layers': 16, 'train_time': 67.23, 'eval_time': 0.45, 'memory_mb': 142.3, 'mse': 0.070, 'mae': 0.176}

Plot saved to \ses\backend\layer_experiment.png
```

### Generated Visualization

The experiment creates `layer_experiment.png` showing:

- **Top plot**: Model accuracy (MSE/MAE) vs number of hidden layers
- **Bottom plot**: Training/evaluation time vs number of hidden layers

This helps identify the optimal balance between model complexity and performance for your specific use case.

## Testing

```bash
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
- **Python 3.8+**: Backend runtime
- **Node.js 16+**: Frontend and Electron
- **Optional**: PyCLIPS for expert system features

---

_For detailed documentation, troubleshooting, and advanced configuration, see the [docs directory](backend/docs/)._
