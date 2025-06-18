# System Configuration and Operations Documentation

This document covers the operational aspects of the Security Evaluation System (SES), including logging configuration, system settings, deployment considerations, and maintenance procedures.

## Overview

The SES application is designed for flexible deployment across development, testing, and production environments. It provides comprehensive logging, configurable behavior, and robust operational controls to ensure reliable security assessments.

## Logging System

The SES application uses Python's standard logging framework for operational monitoring and debugging.

### Logging Architecture

The logging system provides:

- **Console output**: Direct logging to stdout/stderr
- **File logging**: Optional log file output (when configured)
- **Multiple log levels**: DEBUG, INFO, WARNING, ERROR, CRITICAL
- **Module-specific loggers**: Separate loggers for different components

### Log Configuration

#### Basic Setup

```python
import logging

# Basic logging setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

logger.info("Security scan initiated")
logger.warning("Potential security issue detected")
```

### Log Output Formats

#### Standard Format

```log
INFO:main:Security evaluation completed: score=75
WARNING:src.scanner:High-risk port 23 detected
INFO:src.rules:Applying firewall rules
```

### Log File Management

#### Default Log Locations

- **Development**: Console output primarily
- **Production**: Configurable via application settings
- **Evaluation Logs**: `logs/evaluation_log.jsonl` (JSONL format)

The evaluation logging system writes structured JSON entries:

```json
{"timestamp": "2024-01-15T10:30:45", "metrics": {...}, "results": {...}}
```

## Application Configuration

### Environment Variables

The SES application supports basic environment configuration:

#### Core Settings

```bash
# Development
PYTHONPATH=/path/to/ses/backend
CLIPS_RULES_DIR=clips_rules

# Electron Integration
SES_ELECTRON_MODE=true          # When running in Electron
```

### FastAPI Configuration

The main application (`main.py`) provides these endpoints:

- **GET /**: Health check returning `{"message": "Hello World"}`
- **GET /metrics**: Collect and return system security metrics
- **POST /evaluate**: Run security evaluation on provided or collected metrics

## Operational Procedures

### Health Monitoring

#### Health Check

```bash
# Basic health check
curl http://localhost:8000/
# Returns: {"message": "Hello World"}

# Get system metrics
curl http://localhost:8000/metrics

# Run evaluation
curl -X POST http://localhost:8000/evaluate
```

### Performance Monitoring

#### Key Metrics

- **Evaluation Time**: Time to complete security assessment
- **Memory Usage**: Application memory consumption
- **CLIPS Performance**: Rule engine execution time (when available)
- **Error Rate**: Failed evaluations percentage

## Error Handling and Recovery

### Error Categories

1. **System Errors**: Platform compatibility issues, missing dependencies
2. **CLIPS Errors**: Expert system unavailability, rule loading failures
3. **Runtime Errors**: Evaluation failures, scanner issues
4. **Network Errors**: API connectivity issues

### Recovery Strategies

```python
# Graceful degradation example (from rules.py)
def evaluate(metrics, use_clips=None):
    """Evaluate with automatic fallback to basic rules."""
    try:
        if should_use_clips_engine(use_clips):
            return _evaluate_clips(metrics)
    except Exception as e:
        logger.warning(f"CLIPS evaluation failed: {e}, falling back to basic rules")

    return _evaluate_legacy(metrics)
```

## Deployment Configurations

### Development Deployment

#### Local Development

```bash
# Backend
cd backend
python -m uvicorn main:app --reload

# Frontend (separate terminal)
cd frontend
npm run dev
```

### Production Deployment

#### Standalone Backend

```bash
# Production server
uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4
```

#### Electron Distribution

```bash
# Build Electron app
cd frontend
npm run electron:build
```
