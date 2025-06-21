# Tool Configuration Examples

## For Code Analysis Tools

### Initial Setup Command

```bash
set -eux
cd /app
export PIP_BREAK_SYSTEM_PACKAGES=1
# Use base requirements for faster, lighter installation
python -m pip install -r backend/requirements-base.txt || python -m pip install -r backend/requirements.txt
```

### Test Command

```bash
set -eux
cd /app
export PIP_BREAK_SYSTEM_PACKAGES=1
# Install test dependencies if needed
python -m pip install -r backend/requirements-base.txt
# Run tests from backend directory
cd backend && python -m unittest discover -s tests -v
```

## Alternative Commands by Use Case

### Minimal Runtime (Fastest)

```bash
python -m pip install -r backend/requirements-base.txt
```

### Development Environment

```bash
python -m pip install -r backend/requirements-base.txt -r backend/requirements-dev.txt
```

### With GPU Support (Slow but Complete)

```bash
python -m pip install -r backend/requirements-base.txt -r backend/requirements-gpu.txt
```

### Legacy Compatibility

```bash
python -m pip install -r backend/requirements.txt
```

## Size Comparison

| Requirements File | Download Size | Install Time | Use Case |
|-------------------|---------------|--------------|----------|
| requirements-base.txt | ~200MB | ~2 minutes | Production, CI/CD |
| requirements-dev.txt | +50MB | +30 seconds | Development |
| requirements-gpu.txt | +2.5GB | +15 minutes | GPU ML training |
| requirements.txt | ~200MB | ~2 minutes | Compatibility |

## Recommendations

- **For automated tools**: Use `requirements-base.txt`
- **For CI/CD pipelines**: Use `requirements-base.txt`
- **For development**: Use `requirements-base.txt + requirements-dev.txt`
- **For ML with GPU**: Use `requirements-base.txt + requirements-gpu.txt`
- **For legacy compatibility**: Use `requirements.txt`
