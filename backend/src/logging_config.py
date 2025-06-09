"""
Logging configuration for the Security Evaluation System.

Provides structured logging with console and file output options,
JSON formatting capabilities, and standardized logger retrieval.
"""

import json
import logging
import sys
from typing import Dict, Any, Optional
from pathlib import Path


class StructuredJsonFormatter(logging.Formatter):
    """Formats log records as structured JSON for machine readability.

    Provides consistent structured output with standard log fields and
    any additional context provided via extra attributes or dictionaries.
    """

    def format(self, record):
        """Format a log record as a JSON object.

        Args:
            record: LogRecord object to format

        Returns:
            str: JSON-formatted log entry
        """
        log_object = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "name": record.name,
            "message": record.getMessage(),
        }

        # Include exception info if present
        if record.exc_info:
            log_object["exception"] = self.formatException(record.exc_info)

        # Add any 'extra' dictionary passed to the logger
        if hasattr(record, "extra"):
            log_object.update(record.extra)
        elif hasattr(record, "__dict__"):
            # Extract any non-standard fields added to the record
            for key, value in record.__dict__.items():
                if key not in {
                    "args",
                    "asctime",
                    "created",
                    "exc_info",
                    "exc_text",
                    "filename",
                    "funcName",
                    "id",
                    "levelname",
                    "levelno",
                    "lineno",
                    "module",
                    "msecs",
                    "message",
                    "msg",
                    "name",
                    "pathname",
                    "process",
                    "processName",
                    "relativeCreated",
                    "stack_info",
                    "thread",
                    "threadName",
                }:
                    log_object[key] = value

        return json.dumps(log_object)


def setup_logging(
    log_level: str = "INFO", json_format: bool = False, log_file: Optional[str] = None
) -> None:
    """Configure application logging with console and file handlers.

    Sets up the root logger with the specified configuration:
    - Console output to stdout
    - File output with automatic directory creation
    - Optional JSON structured logging
    - Custom log levels with INFO default
    - Reduced verbosity for third-party libraries

    Args:
        log_level: String log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        json_format: Whether to use JSON structured logging
        log_file: Path to log file (default: ./logs/app.log)
    """
    # Determine log file path and ensure its directory exists
    if log_file is None:
        logs_dir = Path("logs")
        logs_dir.mkdir(parents=True, exist_ok=True)
        log_file_path = logs_dir / "app.log"
    else:
        log_file_path = Path(log_file)
        log_file_path.parent.mkdir(parents=True, exist_ok=True)

    # Convert string log level to numeric value
    level = getattr(logging, log_level.upper(), logging.INFO)

    # Create console and file handlers
    handlers = []
    console_handler = logging.StreamHandler(sys.stdout)
    handlers.append(console_handler)

    file_handler = logging.FileHandler(log_file_path)
    handlers.append(file_handler)

    # Select and apply formatter
    if json_format:
        formatter = StructuredJsonFormatter()
    else:
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

    for handler in handlers:
        handler.setFormatter(formatter)

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Remove existing handlers to prevent duplicate log entries
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    for handler in handlers:
        root_logger.addHandler(handler)

    # Reduce verbosity of common third-party libraries
    logging.getLogger("sqlalchemy").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
    logging.getLogger("uvicorn").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("fastapi").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """Get a named logger instance.

    Provides a standardized way to obtain named loggers throughout the application.

    Args:
        name: Logger name, typically __name__ for module-level loggers

    Returns:
        Logger instance with the specified name
    """
    return logging.getLogger(name)
