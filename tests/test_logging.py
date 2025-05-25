"""
Tests for the logging configuration module.

Validates the logging setup, structured JSON formatter, and logger retrieval functionality.
"""

import sys
import unittest
import json
import logging
import tempfile
import os
from pathlib import Path
from io import StringIO
from src.logging_config import setup_logging, get_logger, StructuredJsonFormatter


class TestLoggingConfig(unittest.TestCase):
    """Test cases for logging configuration functionality."""

    def setUp(self):
        """Prepare for tests by saving original logging state."""
        # Save original root logger handlers to restore after tests
        self.original_handlers = logging.getLogger().handlers.copy()
        self.original_level = logging.getLogger().level

        # Reset root logger for clean test environment
        root_logger = logging.getLogger()
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)

    def tearDown(self):
        """Clean up after tests by restoring original logging state."""
        # Restore original root logger handlers and level
        root_logger = logging.getLogger()
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)

        for handler in self.original_handlers:
            root_logger.addHandler(handler)

        root_logger.setLevel(self.original_level)

    def test_structured_json_formatter(self):
        """Test that the JSON formatter correctly formats log records."""
        formatter = StructuredJsonFormatter()

        # Create a log record
        record = logging.LogRecord(
            name="test_logger",
            level=logging.INFO,
            pathname="test_path",
            lineno=42,
            msg="Test message",
            args=(),
            exc_info=None,
        )

        # Format the record
        formatted = formatter.format(record)

        # Parse the JSON result
        log_entry = json.loads(formatted)

        # Check the formatted output
        self.assertEqual(log_entry["level"], "INFO")
        self.assertEqual(log_entry["name"], "test_logger")
        self.assertEqual(log_entry["message"], "Test message")
        self.assertIn("timestamp", log_entry)

    def test_setup_logging_default(self):
        """Test logging setup with default parameters."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            log_file = Path(tmp_dir) / "test.log"
            setup_logging(log_file=str(log_file))

            # Check that the root logger has the expected level
            self.assertEqual(logging.getLogger().level, logging.INFO)

            # Check handlers were created
            root_handlers = logging.getLogger().handlers
            self.assertEqual(len(root_handlers), 2)  # Console and file handler

            # Verify handlers
            handler_types = [type(h) for h in root_handlers]
            self.assertIn(logging.StreamHandler, handler_types)
            self.assertIn(logging.FileHandler, handler_types)

            # Verify log file was created
            self.assertTrue(log_file.exists())

            # Close file handlers before temporary directory cleanup
            for handler in list(logging.getLogger().handlers):
                if isinstance(handler, logging.FileHandler):
                    handler.close()
                    logging.getLogger().removeHandler(handler)

    def test_setup_logging_custom_level(self):
        """Test logging setup with custom log level."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            log_file = Path(tmp_dir) / "debug.log"
            setup_logging(log_level="DEBUG", log_file=str(log_file))

            # Check that the root logger has the expected level
            self.assertEqual(logging.getLogger().level, logging.DEBUG)

            # Close file handlers before temporary directory cleanup
            for handler in list(logging.getLogger().handlers):
                if isinstance(handler, logging.FileHandler):
                    handler.close()
                    logging.getLogger().removeHandler(handler)

    def test_setup_logging_json_format(self):
        """Test logging setup with JSON formatting."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            log_file = Path(tmp_dir) / "json.log"
            setup_logging(json_format=True, log_file=str(log_file))

            # Check that handlers use JSON formatter
            for handler in logging.getLogger().handlers:
                self.assertIsInstance(handler.formatter, StructuredJsonFormatter)

            # Close file handlers before temporary directory cleanup
            for handler in list(logging.getLogger().handlers):
                if isinstance(handler, logging.FileHandler):
                    handler.close()
                    logging.getLogger().removeHandler(handler)

    def test_get_logger(self):
        """Test that get_logger returns a logger with the correct name."""
        logger = get_logger("test.namespace")
        self.assertEqual(logger.name, "test.namespace")

    def test_logging_output(self):
        """Test that logging produces expected output."""
        # Setup logging with StringIO to capture output
        string_io = StringIO()
        handler = logging.StreamHandler(string_io)
        formatter = logging.Formatter("%(levelname)s - %(message)s")
        handler.setFormatter(formatter)

        test_logger = logging.getLogger("test.output")
        test_logger.setLevel(logging.INFO)
        test_logger.addHandler(handler)

        # Log a test message
        test_message = "This is a test log message"
        test_logger.info(test_message)

        # Check the output
        output = string_io.getvalue().strip()
        self.assertEqual(output, f"INFO - {test_message}")

    def test_structured_json_formatter_with_exception(self):
        """Test that the JSON formatter correctly formats log records with exceptions."""
        formatter = StructuredJsonFormatter()

        # Create an exception
        try:
            raise ValueError("Test exception")
        except ValueError:
            exc_info = sys.exc_info()

        # Create a log record with exception info
        record = logging.LogRecord(
            name="test_logger",
            level=logging.ERROR,
            pathname="test_path",
            lineno=42,
            msg="Exception occurred",
            args=(),
            exc_info=exc_info,
        )

        # Format the record
        formatted = formatter.format(record)

        # Parse the JSON result
        log_entry = json.loads(formatted)

        # Check exception info was included
        self.assertIn("exception", log_entry)
        self.assertIn("ValueError: Test exception", log_entry["exception"])

    def test_structured_json_formatter_with_extra_fields(self):
        """Test that the JSON formatter correctly includes extra fields."""
        formatter = StructuredJsonFormatter()

        # Create a log record with extra attribute
        record = logging.LogRecord(
            name="test_logger",
            level=logging.INFO,
            pathname="test_path",
            lineno=42,
            msg="Test message with extra",
            args=(),
            exc_info=None,
        )
        # Add an extra field directly to record.__dict__
        record.request_id = "123456"
        record.user_id = "user-789"

        # Format the record
        formatted = formatter.format(record)

        # Parse the JSON result
        log_entry = json.loads(formatted)

        # Check extra fields were included
        self.assertEqual(log_entry["request_id"], "123456")
        self.assertEqual(log_entry["user_id"], "user-789")

    def test_setup_logging_default_file_path(self):
        """Test logging setup with default log file path (None)."""
        # Save original directory and create a temporary working directory
        original_dir = os.getcwd()
        with tempfile.TemporaryDirectory() as tmp_dir:
            try:
                # Change to the temporary directory
                os.chdir(tmp_dir)

                # Call setup_logging with default log_file (None)
                setup_logging(log_file=None)

                # Check logs directory was created
                logs_dir = Path("logs")
                self.assertTrue(logs_dir.exists())
                self.assertTrue(logs_dir.is_dir())

                # Check default log file was created
                default_log_file = logs_dir / "app.log"
                self.assertTrue(default_log_file.exists())

                # Close file handlers before temporary directory cleanup
                for handler in list(logging.getLogger().handlers):
                    if isinstance(handler, logging.FileHandler):
                        handler.close()
                        logging.getLogger().removeHandler(handler)
            finally:
                # Return to original directory
                os.chdir(original_dir)

    def test_setup_logging_creates_parent_dirs(self):
        """Test that setup_logging creates parent directories for log files."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            # Create a multi-level path that doesn't exist yet
            nested_log_path = Path(tmp_dir) / "nested" / "dirs" / "logs" / "test.log"

            # This should create all parent directories
            setup_logging(log_file=str(nested_log_path))

            # Verify directories were created
            self.assertTrue(nested_log_path.parent.exists())
            self.assertTrue(nested_log_path.exists())

            # Close file handlers before temporary directory cleanup
            for handler in list(logging.getLogger().handlers):
                if isinstance(handler, logging.FileHandler):
                    handler.close()
                    logging.getLogger().removeHandler(handler)

    def test_third_party_logger_levels(self):
        """Test that third-party loggers are set to appropriate levels."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            log_file = Path(tmp_dir) / "third_party.log"
            setup_logging(log_file=str(log_file))

            # Verify third-party logger levels
            self.assertEqual(logging.getLogger("sqlalchemy").level, logging.WARNING)
            self.assertEqual(
                logging.getLogger("sqlalchemy.engine").level, logging.WARNING
            )
            self.assertEqual(logging.getLogger("uvicorn").level, logging.WARNING)
            self.assertEqual(logging.getLogger("uvicorn.access").level, logging.WARNING)
            self.assertEqual(logging.getLogger("fastapi").level, logging.WARNING)

            # Close file handlers before temporary directory cleanup
            for handler in list(logging.getLogger().handlers):
                if isinstance(handler, logging.FileHandler):
                    handler.close()
                    logging.getLogger().removeHandler(handler)

    def test_structured_json_formatter_with_record_extra(self):
        """Test that the JSON formatter correctly handles record.extra attribute."""
        formatter = StructuredJsonFormatter()

        # Create a log record
        record = logging.LogRecord(
            name="test_logger",
            level=logging.INFO,
            pathname="test_path",
            lineno=42,
            msg="Test message with extra attribute",
            args=(),
            exc_info=None,
        )

        # Add an 'extra' attribute to the record (this is what we're testing)
        record.extra = {"transaction_id": "txn-123", "correlation_id": "corr-456"}

        # Format the record
        formatted = formatter.format(record)

        # Parse the JSON result
        log_entry = json.loads(formatted)

        # Check that fields from record.extra were included
        self.assertEqual(log_entry["transaction_id"], "txn-123")
        self.assertEqual(log_entry["correlation_id"], "corr-456")

    def test_setup_logging_removes_existing_handlers(self):
        """Test that setup_logging removes existing handlers to avoid duplicates."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            log_file = Path(tmp_dir) / "handlers.log"

            # Add a test handler to the root logger before setup_logging
            root_logger = logging.getLogger()
            test_handler = logging.StreamHandler(StringIO())
            root_logger.addHandler(test_handler)

            # Count handlers before setup_logging
            handler_count_before = len(root_logger.handlers)
            self.assertGreaterEqual(handler_count_before, 1)
            self.assertIn(test_handler, root_logger.handlers)

            # Call setup_logging
            setup_logging(log_file=str(log_file))

            # Verify the test handler was removed
            self.assertNotIn(test_handler, root_logger.handlers)

            # Should have exactly 2 handlers (console and file)
            self.assertEqual(len(root_logger.handlers), 2)

            # Close file handlers before temporary directory cleanup
            for handler in list(logging.getLogger().handlers):
                if isinstance(handler, logging.FileHandler):
                    handler.close()
                    logging.getLogger().removeHandler(handler)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
