"""Structured JSON logging for Google Cloud Logging with secret redaction."""

import json
import logging
import re
import sys
import time
from typing import Any, Dict

# Redaction patterns for sensitive tokens and keys
TOKEN_PATTERNS = [
    re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,255}"),
    re.compile(r"Bearer\s+[A-Za-z0-9_\-\.]{20,}", re.IGNORECASE),
    re.compile(r"sha256=[a-fA-F0-9]{64}"),
]


def redact_sensitive_data(text: str) -> str:
    """Redacts known tokens, secrets, and hashes from text strings."""
    redacted = text
    for pattern in TOKEN_PATTERNS:
        redacted = pattern.sub("[REDACTED_SECRET]", redacted)
    return redacted


class CloudLoggingJsonFormatter(logging.Formatter):
    """Formats log records as structured JSON compliant with Google Cloud Logging."""

    LEVEL_MAP = {
        "DEBUG": "DEBUG",
        "INFO": "INFO",
        "WARNING": "WARNING",
        "ERROR": "ERROR",
        "CRITICAL": "CRITICAL",
    }

    def format(self, record: logging.LogRecord) -> str:
        msg = redact_sensitive_data(record.getMessage())
        log_payload: Dict[str, Any] = {
            "severity": self.LEVEL_MAP.get(record.levelname, "INFO"),
            "message": msg,
            "timestamp": time.time(),
            "logger": record.name,
            "module": record.module,
            "line": record.lineno,
        }

        # Include custom extra fields if present
        if hasattr(record, "report_id"):
            log_payload["report_id"] = record.report_id
        if hasattr(record, "delivery_id"):
            log_payload["delivery_id"] = record.delivery_id
        if hasattr(record, "event"):
            log_payload["event"] = record.event
        if hasattr(record, "verdict"):
            log_payload["verdict"] = record.verdict

        if record.exc_info:
            log_payload["exception"] = redact_sensitive_data(
                self.formatException(record.exc_info)
            )

        return json.dumps(log_payload)


def configure_cloud_logging(level: int = logging.INFO) -> None:
    """Configures the root logger with CloudLoggingJsonFormatter on stdout."""
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(CloudLoggingJsonFormatter())

    root = logging.getLogger()
    root.setLevel(level)

    # Replace existing handlers
    root.handlers.clear()
    root.addHandler(handler)
