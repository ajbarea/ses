# SES - Security Evaluation System

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

## Environment Setup

### Creating and Activating a Virtual Environment

```bash
# Create a new virtual environment
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
fastapi dev main.py
```

### API Endpoints

- `/` - Health check
- `/metrics` - Get raw system security metrics
- `/evaluate` - Run security evaluation and get results

### Viewing the API Documentation

- Swagger UI: <http://127.0.0.1:8000/docs>

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
cd tests
python -m unittest discover
```
