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
uvicorn main:app --reload
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
