# SES - Security Evaluation System

[![codecov](https://codecov.io/gh/ajbarea/ses/graph/badge.svg?token=3PfdAPHO7K)](https://codecov.io/gh/ajbarea/ses) [![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=ajbarea_ses&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=ajbarea_ses)

## Introduction

A Windows security assessment tool that collects system metrics, evaluates them against security rules, and generates reports with findings and recommendations.

## Features

- Collects security metrics from Windows systems:
  - Patch status
  - Open network ports
  - Running services
  - Firewall configuration
  - Antivirus status
  - Password policy
- Evaluates security using either:
  - Basic rule engine (always available)
  - Advanced CLIPS expert system (when PyCLIPS is installed)
- Provides security score, grade, and detailed findings
- Exposes API endpoints via FastAPI
- Logs evaluations for historical tracking

## System Architecture

The following diagram illustrates the architecture of the SES application:

![System Architecture Diagram](https://www.mermaidchart.com/raw/0e79dd72-8d03-4177-8504-0c572454a15d?theme=light&version=v0.1&format=svg)

## Environment Setup

### Creating and Activating a Virtual Environment

```bash
# Create a new virtual environment
cd backend
python -m venv .venv

# Activate the virtual environment
# For Windows
source .venv/Scripts/activate
# For Unix/MacOS
source .venv/bin/activate
```

### Verifying the Environment

```bash
# Check which Python is being used (should point to your .venv Python)
which python

# Verify Python version
python --version
```

### Package Management

```bash
# Upgrade pip first
python -m pip install --upgrade pip

# Install dependencies from requirements.txt
pip install -r requirements.txt
```

## Running the FastAPI Server

```bash
uvicorn main:app --reload --reload-exclude logs/
```

## Running the Frontend

Open a new terminal, navigate to the `frontend` folder, install dependencies, and start the dev server:

```bash
cd frontend
npm install
npm run dev
```

Create a `.env.local` file in `frontend/` to set the frontend API endpoint:

```text
NEXT_PUBLIC_API_URL=http://localhost:8000
```

The frontend will be available at <http://localhost:3000>

### API Endpoints

- `/` - Health check
- `/metrics` - Get raw system security metrics
- `/evaluate` - Run security evaluation and get results

### Viewing the API Documentation

- Swagger UI: <http://localhost:8000/docs>

## Logs

Evaluation outputs are written to `logs/evaluation_log.jsonl` (one JSON record per line).

## CLIPS Expert System

The CLIPS expert system provides advanced rule-based evaluation with:

- Pattern matching and rule chaining
- Dynamic scoring based on multiple factors
- Detailed explanations for findings
- Rule prioritization

### Adding Custom CLIPS Rules

Create new `.clp` files in the `clips_rules` directory. For example:

```clips
(defrule suspicious-login-attempts
    (login-attempts (count ?n&:(> ?n 5)) (period "hour"))
    =>
    (assert (finding
        (rule-name "suspicious_logins")
        (level "warning")
        (description (str-cat "High number of login attempts (" ?n ") in the last hour."))
        (recommendation "Investigate potential brute force attempts.")
    ))
)
```

### Available CLIPS Rule Files

The system includes several specialized rule files:

- `patch_rules.clp` - Evaluates Windows update status
- `port_rules.clp` - Checks for open/high-risk network ports
- `firewall_rules.clp` - Analyzes Windows Firewall profile status
- `password_rules.clp` - Validates password policy strength
- `antivirus_rules.clp` - Checks antivirus software status and configuration

## Machine Learning Dataset Generation

SES can generate datasets for training ML models that mimic the expert system's behavior.

### Generating Training Data

```bash
cd backend

# Generate a basic dataset
python -m src.data_generator -n 1000 -o security_dataset.csv

# Generate train/test split (0.8 => 80% train - 20% test)
python -m src.data_generator -n 1000 --split 0.8 -o security_data_split.csv
```

### Dataset Structure

The generated CSV contains:

**Input Features:**

- `patch_status`, `patch_hotfixes_count` - System patch information
- `ports_count` - Number of open network ports
- `services_total`, `services_running`, `services_stopped` - Service counts
- `firewall_domain`, `firewall_private`, `firewall_public` - Firewall states
- `antivirus_count`, `antivirus_enabled` - Antivirus status
- `password_min_length`, `password_max_age` - Password policy

**Target Variables:**

- `target_score` - Expert system security score (0-100)
- `target_grade` - Security grade (Excellent, Good, Fair, Poor, Critical Risk)

## Machine Learning Training & Testing

SES includes a comprehensive ML framework for training neural networks to approximate the Expert System's behavior through supervised learning.

### Training a Security Neural Network

Use the dedicated training script to train a PyTorch model that learns to mimic the Expert System:

```bash
cd backend

# First, generate training data if you haven't already:
python -m src.data_generator -n 1000 --split 0.8 -o security_data_split.csv

# Train with default parameters (100 epochs, 128 hidden units)
python train_security_model.py

# The script expects these files to exist:
# - security_data_split_train.csv (training data)
# - security_data_split_test.csv (testing data)
```

#### Training Script Parameters

The `train_security_model.py` script uses these default parameters:

- **Epochs**: 100 (training iterations)
- **Hidden Size**: 128 neurons in hidden layers
- **Learning Rate**: 0.001
- **Batch Size**: 16 samples per training batch
- **GPU**: Automatically uses CUDA if available

To modify these parameters, edit the script or use the programmatic API:

```python
from src.ml_trainer import train_model, evaluate_security_model

# Train with custom parameters
model_data = train_model(
    "security_data_split_train.csv",
    model_type="security",
    target_col="target_score",
    epochs=50,           # Reduce training time
    hidden_size=64,      # Smaller network
    lr=0.001,           # Learning rate
    batch_size=32,      # Larger batches
    no_cuda=True        # Force CPU usage
)
```

#### Expected Training Output

When you run `python train_security_model.py`, you'll see output similar to:

```bash
Training Security Prediction Model...
==================================================
Epoch 10/100, Loss: 0.0156
Epoch 20/100, Loss: 0.0089
Epoch 30/100, Loss: 0.0045
...
Epoch 100/100, Loss: 0.0012
Training completed. Final validation MSE: 0.0023

Evaluating on test set...
Test MSE: 0.0018
Test MAE: 3.2
Test RMSE: 0.0424
R² Score: 0.987
Grade Classification Accuracy: 0.95
Expert System Consistency: 0.93

Sample Predictions vs Actual:
------------------------------------------------------------
Sample | Predicted | Actual | Error | Expert System Approximation
------------------------------------------------------------
   1   |   98.2   |  100.0  |  1.8 | Excellent
   2   |   45.1   |   45.0  |  0.1 | Excellent
   ...

==================================================
EXPERT SYSTEM APPROXIMATION QUALITY ASSESSMENT
==================================================
🟢 EXCELLENT: Your ML model closely approximates the Expert System
Average prediction error: 3.20 points
R² correlation with Expert System: 0.987
```

## Testing

Run the test suite with:

```bash
python -m unittest discover
```

## Build

### 1. Backend

```bash
cd backend
python -m venv .venv_backend_build
source .venv_backend_build/Scripts/activate

# update pip and install deps
pip install --upgrade pip
pip install -r requirements.txt

# exit venv
deactivate
```

### 2. Frontend & Electron

```bash
cd frontend

# install web dependencies
npm install

# build React/Next output and package Electron app
npm run electron:build
```

### 3. Verify Output

After a successful run you’ll find:

- `backend/dist/` – compiled backend artifacts
- `frontend/out/` – Next.js static export
- `frontend/dist_electron/` – Electron installer per-OS

### Acknowledgements

AI assistance from OpenAI, Anthropic, and Google models supported this project through code reviews, debugging, CLIPS rule syntax, documentation, and Electron build scripting.
