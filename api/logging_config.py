"""
Structured JSON logging configuration for Nubicustos API.

Provides:
- JSON formatted log output
- Request ID tracking via correlation IDs
- Configurable log levels via environment variables
- Context-aware logging with request metadata
"""

import json
import logging
import sys
import uuid
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import Any

# Context variable for request correlation ID
request_id_ctx: ContextVar[str | None] = ContextVar("request_id", default=None)


def get_request_id() -> str | None:
    """Get the current request ID from context."""
    return request_id_ctx.get()


def set_request_id(request_id: str | None = None) -> str:
    """Set a request ID in the current context. Generates one if not provided."""
    if request_id is None:
        request_id = str(uuid.uuid4())
    request_id_ctx.set(request_id)
    return request_id


class JSONFormatter(logging.Formatter):
    """Custom JSON formatter for structured logging."""

    def __init__(self, service_name: str = "nubicustos-api"):
        super().__init__()
        self.service_name = service_name

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        log_data: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "service": self.service_name,
        }

        # Add request ID if available
        request_id = get_request_id()
        if request_id:
            log_data["request_id"] = request_id

        # Add source location
        log_data["source"] = {
            "file": record.filename,
            "line": record.lineno,
            "function": record.funcName,
        }

        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = {
                "type": record.exc_info[0].__name__ if record.exc_info[0] else None,
                "message": str(record.exc_info[1]) if record.exc_info[1] else None,
                "traceback": self.formatException(record.exc_info),
            }

        # Add any extra fields passed to the logger
        extra_fields = {}
        for key, value in record.__dict__.items():
            if key not in (
                "name",
                "msg",
                "args",
                "created",
                "filename",
                "funcName",
                "levelname",
                "levelno",
                "lineno",
                "module",
                "msecs",
                "pathname",
                "process",
                "processName",
                "relativeCreated",
                "stack_info",
                "exc_info",
                "exc_text",
                "thread",
                "threadName",
                "message",
                "taskName",
            ):
                extra_fields[key] = value

        if extra_fields:
            log_data["extra"] = extra_fields

        return json.dumps(log_data, default=str)


class TextFormatter(logging.Formatter):
    """Standard text formatter with request ID."""

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as text with request ID."""
        request_id = get_request_id()
        request_id_str = f"[{request_id[:8]}] " if request_id else ""

        timestamp = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")
        return f"{timestamp} - {request_id_str}{record.levelname} - {record.name} - {record.getMessage()}"


def setup_logging(
    log_level: str = "INFO", log_format: str = "json", service_name: str = "nubicustos-api"
) -> logging.Logger:
    """
    Configure structured logging for the application.

    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_format: Output format ("json" or "text")
        service_name: Name to include in log entries

    Returns:
        Configured root logger
    """
    # Get numeric log level
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)

    # Create handler
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(numeric_level)

    # Set formatter based on format preference
    if log_format.lower() == "json":
        handler.setFormatter(JSONFormatter(service_name))
    else:
        handler.setFormatter(TextFormatter())

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)

    # Remove existing handlers to avoid duplicates
    for existing_handler in root_logger.handlers[:]:
        root_logger.removeHandler(existing_handler)

    root_logger.addHandler(handler)

    # Reduce noise from external libraries
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)

    return root_logger


def get_logger(name: str) -> logging.Logger:
    """Get a logger with the given name."""
    return logging.getLogger(name)


class LogContext:
    """Context manager for adding extra fields to log entries."""

    def __init__(self, logger: logging.Logger, **extra_fields):
        self.logger = logger
        self.extra_fields = extra_fields
        self.old_extra = {}

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    def info(self, msg: str, **kwargs):
        """Log info with extra context."""
        self.logger.info(msg, extra={**self.extra_fields, **kwargs})

    def warning(self, msg: str, **kwargs):
        """Log warning with extra context."""
        self.logger.warning(msg, extra={**self.extra_fields, **kwargs})

    def error(self, msg: str, **kwargs):
        """Log error with extra context."""
        self.logger.error(msg, extra={**self.extra_fields, **kwargs})

    def debug(self, msg: str, **kwargs):
        """Log debug with extra context."""
        self.logger.debug(msg, extra={**self.extra_fields, **kwargs})
