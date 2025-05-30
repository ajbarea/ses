"""
Configures logging handlers and formatters for both console and file output.
"""

import json
import logging
import sys
from typing import Dict, Any, Optional
from pathlib import Path


class StructuredJsonFormatter(logging.Formatter):
    """Format log records as structured JSON objects."""

    def format(self, record):
        log_object = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "name": record.name,
            "message": record.getMessage(),
        }

        if record.exc_info:  # Add exception information if present
            log_object["exception"] = self.formatException(record.exc_info)

        # Add any 'extra' dictionary passed to the logger
        if hasattr(record, "extra"):
            log_object.update(record.extra)
        elif hasattr(record, "__dict__"):
            # Extract any extra fields added to the record
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
    """Set up log level, console/file handlers, and format (JSON or plain)."""
    # Determine log file path and ensure its directory exists
    if log_file is None:
        logs_dir = Path("logs")
        logs_dir.mkdir(parents=True, exist_ok=True)
        log_file_path = logs_dir / "app.log"
    else:
        log_file_path = Path(log_file)
        log_file_path.parent.mkdir(parents=True, exist_ok=True)

    level = getattr(logging, log_level.upper(), logging.INFO)

    handlers = []
    console_handler = logging.StreamHandler(sys.stdout)
    handlers.append(console_handler)

    file_handler = logging.FileHandler(log_file_path)
    handlers.append(file_handler)

    if json_format:
        formatter = StructuredJsonFormatter()
    else:
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

    for handler in handlers:
        handler.setFormatter(formatter)

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
    """Obtain a logger instance by name."""
    return logging.getLogger(name)
