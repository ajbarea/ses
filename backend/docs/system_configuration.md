# System Configuration and Operations Documentation

This document covers the operational aspects of the Security Evaluation System (SES), including logging configuration, system settings, deployment considerations, and maintenance procedures.

## Overview

The SES application is designed for flexible deployment across development, testing, and production environments. It provides comprehensive logging, configurable behavior, and robust operational controls to ensure reliable security assessments.

## Logging System

The SES application uses a sophisticated logging system built on Python's standard logging framework with custom configuration through the `src.logging_config` module.

### Logging Architecture

The logging system provides:

- **Console output**: Direct logging to stdout via StreamHandler
- **File logging**: Automatic log file creation with directory management
- **Multiple log levels**: DEBUG, INFO, WARNING, ERROR, CRITICAL
- **Module-specific loggers**: Separate loggers for different components
- **JSON formatting**: Optional structured JSON logging for machine readability
- **Third-party library control**: Reduced verbosity for common libraries

### Log Configuration

#### Centralized Setup

```python
from src.logging_config import setup_logging, get_logger

# Configure logging system
setup_logging(
    log_level="INFO",
    json_format=False,
    log_file="logs/app.log"
)

# Get module-specific logger
logger = get_logger(__name__)

logger.info("Security scan initiated")
logger.warning("Potential security issue detected")
```

### Log Output Formats

#### Standard Format

```log
2024-12-23 14:30:45 - main - INFO - Security evaluation completed: score=75
2024-12-23 14:30:46 - src.scanner - WARNING - High-risk port 23 detected
2024-12-23 14:30:47 - src.rules - INFO - Applying firewall rules
```

#### JSON Format (when enabled)

```json
{
  "timestamp": "2024-12-23 14:30:45",
  "level": "INFO",
  "name": "main",
  "message": "Security evaluation completed: score=75"
}
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

# Logging Configuration
LOG_LEVEL=INFO                  # DEBUG, INFO, WARNING, ERROR, CRITICAL
JSON_LOG_FORMAT=false          # Enable JSON structured logging
LOG_FILE=logs/app.log          # Custom log file path

# Electron Integration
SES_ELECTRON_MODE=true          # When running in Electron
SES_ELECTRON_PACKAGED=1         # Set by Electron when packaged
```

### FastAPI Configuration

The main application (`main.py`) provides these endpoints:

- **GET /**: Health check returning `{"message": "Hello World"}`
- **GET /metrics**: Collect and return system security metrics
- **GET /evaluate**: Run security evaluation on provided or collected metrics

#### Environment Variable Configuration

The application uses environment variables for configuration:

- `LOG_LEVEL`: Controls logging verbosity (default: "INFO")
- `JSON_LOG_FORMAT`: Enables JSON structured logging (default: "False")
- `LOG_FILE`: Custom log file path (default: "logs/app.log")

#### Specialized Logging

The application creates a dedicated evaluation logger for structured JSONL output:

```python
eval_logger = get_logger("evaluation")
eval_handler = logging.FileHandler("logs/evaluation_log.jsonl")
eval_handler.setFormatter(logging.Formatter("%(message)s"))
eval_logger.addHandler(eval_handler)
```

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
curl http://localhost:8000/evaluate
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

### Logging Integration

The system uses the sophisticated logging configuration to capture and handle errors:

- **Error Tracking**: All errors are logged with appropriate severity levels
- **Third-party Library Management**: Reduced verbosity for common libraries prevents log noise
- **Structured Output**: JSON logging available for automated error monitoring
- **Evaluation Tracking**: Dedicated JSONL logging for evaluation-specific errors

## Deployment Configurations

### Development Deployment

#### Local Development

```bash
# Backend
cd backend
python -m uvicorn main:app --reload --reload-exclude logs/

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

# Build for specific platforms
npm run electron:build:win
npm run electron:build:mac
```
