# SES - Security Evaluation System

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
