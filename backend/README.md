# SES Backend - Requirements Overview

This directory contains multiple requirements files to optimize installation size and speed:

## 📦 Requirements Files

### `requirements-base.txt` (~200MB)

**Core runtime dependencies** - Use this for production deployments and CI/CD

- FastAPI web framework
- ML libraries (scikit-learn, pandas, torch-cpu)
- Security scanning tools (psutil, clipspy)
- Platform-specific dependencies (wmi for Windows)

### `requirements-dev.txt` (~50MB)

**Development and build tools** - Add this for development work

- PyInstaller (for building executables)
- Testing frameworks (pytest, coverage)
- Code quality tools (black, flake8)

### `requirements-gpu.txt` (~2.7GB)

**GPU-accelerated PyTorch** - Only install if you need GPU support

- Full CUDA-enabled PyTorch
- GPU libraries for ML acceleration
- **Warning**: Very large download, only use if necessary

### `requirements.txt`

**Compatibility file** - References base requirements for tools that expect this filename

## 🚀 Quick Setup

```bash
# Basic installation (recommended for most cases)
./setup.sh base

# Development environment
./setup.sh dev

# GPU support (only if needed)
./setup.sh gpu

# Everything
./setup.sh full
```

## 📋 Manual Installation

```bash
# Production deployment
pip install -r requirements-base.txt

# Development work
pip install -r requirements-base.txt -r requirements-dev.txt

# With GPU support
pip install -r requirements-base.txt -r requirements-gpu.txt
```
