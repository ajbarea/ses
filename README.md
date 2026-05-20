<div align="center">

# 🛡️ Security Evaluation System

### Windows security assessment via Python rules, a CLIPS expert system, ML, or federated learning

*Collects system metrics (patches, ports, services, firewall, antivirus, password policy) and produces scored reports with actionable findings.*

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Node.js](https://img.shields.io/badge/Node.js-22-339933?style=flat-square&logo=node.js&logoColor=white)](https://nodejs.org)
[![CLIPS](https://img.shields.io/badge/CLIPS-expert%20system-orange?style=flat-square)](https://www.clipsrules.net/)
[![Codecov](https://codecov.io/gh/ajbarea/ses/graph/badge.svg?token=3PfdAPHO7K)](https://codecov.io/gh/ajbarea/ses)
[![Quality Gate](https://sonarcloud.io/api/project_badges/measure?project=ajbarea_ses&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=ajbarea_ses)

</div>

---

## What is this?

SES is a Windows-focused security assessment tool that collects host metrics and scores them through one of four interchangeable evaluation backends:

1. **Python rule engine** — always available, deterministic baseline
2. **CLIPS expert system** — rule-chaining over patch/port/firewall/password/antivirus facts
3. **Neural network** — trained to approximate the expert system's scoring at lower latency
4. **Federated learning** — privacy-preserving collaborative model training across clients

Front-end is Next.js + Electron; back-end is FastAPI. The CLIPS rules live in `backend/src/clips_rules/` and are version-controlled alongside the code.

## Features

- **Metric collection**: patch status, open ports, services, firewall, antivirus, password policy
- **Dual deterministic engines**: basic Python rules + CLIPS expert system
- **ML training**: neural networks that approximate the expert system at lower runtime cost
- **Federated learning**: privacy-preserving model training across simulated clients
- **REST API**: FastAPI endpoints for integration with other tooling
- **Security scoring**: numeric scores, letter grades, and detailed findings with recommendations

## Quick Start

### Backend

```bash
cd backend
python -m venv .venv
source .venv/Scripts/activate    # Windows
python -m pip install --upgrade pip
pip install -r requirements.txt
uvicorn main:app --reload --reload-exclude logs/
```

### Frontend

```bash
cd frontend
npm install
echo "NEXT_PUBLIC_API_URL=http://localhost:8000" > .env.local
npm run dev
```

## API Endpoints

| Endpoint | Purpose |
|----------|---------|
| `GET /` | Health check |
| `GET /metrics` | System security metrics |
| `GET /evaluate` | Security evaluation results |
| `GET /docs` | Interactive OpenAPI docs |

## Documentation

### Core

- **[Security Evaluation System](backend/docs/security_evaluation.md)** — metric collection, rule evaluation, scoring
- **[Expert System Implementation](backend/docs/expert_system.md)** — CLIPS-based advanced evaluation
- **[System Configuration](backend/docs/system_configuration.md)** — deployment, logging, operations

### Advanced

- **[Machine Learning Pipeline](backend/docs/machine_learning_pipeline.md)** — neural network training to approximate the expert system
- **[Federated Learning Pipeline](backend/docs/federated_learning_pipeline.md)** — privacy-preserving collaborative model training
- **[Synthetic Data Generation](backend/docs/data_generation.md)** — generate training datasets
- **[System Architecture](backend/docs/models/ses_system_architecture.mermaid)** — visual system overview

### Rule files

CLIPS rules live in `backend/src/clips_rules/`:

- [`patch_rules.clp`](backend/src/clips_rules/patch_rules.clp) — Windows update evaluation
- [`port_rules.clp`](backend/src/clips_rules/port_rules.clp) — network security assessment
- [`firewall_rules.clp`](backend/src/clips_rules/firewall_rules.clp) — firewall analysis
- [`password_rules.clp`](backend/src/clips_rules/password_rules.clp) — password policy validation
- [`antivirus_rules.clp`](backend/src/clips_rules/antivirus_rules.clp) — antivirus status checking

## Machine Learning Workflow

```bash
# Generate training data
cd backend
python -m src.data_generator -n 1000 --split 0.8 -o security_data_split.csv

# Train neural network
cd ml/experiments
python train_security_model.py
```

The `ml_experiments.py` script sweeps over architectures (hidden layers, neurons per layer) to find the best accuracy/efficiency trade-off. Set the experiment mode (`layer`, `neuron`, or `both`) at the top of the script. Output plots and logs land in `docs/experiments/`.

## Federated Learning Workflow

```bash
cd backend
python -m fl.experiments.fl_experiments
```

Generates federated datasets and orchestrates collaborative training across simulated clients. Individual experiments available:

```bash
python -m fl.experiments.convergence_experiment      # does the federated model converge?
python -m fl.experiments.aggregation_experiment      # FedAvg vs weighted vs median vs secure
python -m fl.experiments.privacy_experiment          # noise injection impact on performance
```

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

- **Windows**: primary platform for security scanning
- **Python 3.11**: backend runtime (Python 3.13 has PyTorch compatibility issues)
- **Node.js 22**: frontend and Electron
- **Optional**: PyCLIPS for the expert system backend

## License

[MIT](LICENSE)

---

_For detailed documentation, troubleshooting, and advanced configuration, see [`backend/docs/`](backend/docs/)._

---

<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://res.cloudinary.com/dumwa1w5x/image/upload/q_auto,f_auto,e_negate/v1779302138/brand_gwqy8l.png">
  <img src="https://res.cloudinary.com/dumwa1w5x/image/upload/q_auto,f_auto/v1779302138/brand_gwqy8l.png" alt="" height="16" />
</picture>&nbsp;&nbsp;2026 <a href="https://ajbarea.github.io/">AJ Barea</a>

</div>
