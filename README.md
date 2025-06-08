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
        (details ?n)
        (recommendation "Investigate potential brute force attempts.")
    ))
    (assert (score (value -10) (type penalty)))
)
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

## Acknowledgements

AI assistance from OpenAI, Anthropic, and Google models supported this project through code reviews, debugging, CLIPS rule syntax, documentation, and Electron build scripting.
