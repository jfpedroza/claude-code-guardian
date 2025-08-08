"""Utility functions for Claude Code Guardian."""

import logging
import logging.handlers
import os
from pathlib import Path

from platformdirs import user_log_dir


def _is_running_tests() -> bool:
    """Check if we're running in a test environment."""
    return (
        "pytest" in os.environ.get("_", "")
        or "PYTEST_CURRENT_TEST" in os.environ
        or "pytest" in str(os.environ.get("_PYTEST_RUNNER", ""))
    )


def setup_logging(log_level: str = "INFO") -> None:
    """
    Setup file-only logging for Claude Code Guardian.

    During tests, logging is disabled to avoid interfering with user files.

    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    """
    # Remove any existing handlers to avoid duplicate logs
    root_logger = logging.getLogger()
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Skip file logging during tests
    if _is_running_tests():
        # Use a null handler during tests to completely silence logging
        null_handler = logging.NullHandler()
        root_logger.addHandler(null_handler)
        root_logger.setLevel(logging.CRITICAL + 1)  # Disable all logging
        root_logger.propagate = False
        return

    log_file = get_log_file_path()
    log_file.parent.mkdir(parents=True, exist_ok=True)

    # Configure rotating file handler
    file_handler = logging.handlers.RotatingFileHandler(
        log_file,
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=5,
        encoding="utf-8",
    )

    # Set formatter
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    )
    file_handler.setFormatter(formatter)

    # Configure root logger
    root_logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))
    root_logger.addHandler(file_handler)

    # Disable console output by setting a no-op handler
    # This ensures no output goes to stdout/stderr
    root_logger.propagate = False


def get_log_file_path() -> Path:
    """Get the path to the current log file."""
    log_dir = Path(user_log_dir("claude-code-guardian"))
    return log_dir / "guardian.log"
