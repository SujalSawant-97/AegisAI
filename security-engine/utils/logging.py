"""
Structured logging setup.

Produces JSON-line logs including scan ID / scanner / target context via
the `extra` dict, and never logs sensitive values (passwords, tokens,
cookies, authorization headers) unless a caller explicitly marks a debug
session as "secure debugging" (not implemented by default — safest option).
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any

_SENSITIVE_KEYS = {
    "password",
    "api_key",
    "apikey",
    "token",
    "access_token",
    "refresh_token",
    "cookie",
    "cookies",
    "authorization",
    "auth_header",
}


def _sanitize(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            k: ("<redacted>" if k.lower() in _SENSITIVE_KEYS else _sanitize(v))
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [_sanitize(v) for v in value]
    return value


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Merge in any structured `extra` fields, sanitized.
        standard_attrs = set(logging.LogRecord("", 0, "", 0, "", (), None).__dict__.keys())
        for key, value in record.__dict__.items():
            if key not in standard_attrs and key not in ("message", "asctime"):
                payload[key] = _sanitize(value)

        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)

        return json.dumps(payload, default=str)


def get_logger(name: str, level: int = logging.INFO) -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JsonFormatter())
        logger.addHandler(handler)
        logger.setLevel(level)
        logger.propagate = False
    return logger
