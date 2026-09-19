"""JSON logging plus a helper for structured security events.

Security events never contain passwords or tokens. E-mail addresses are logged
as a truncated SHA-256 so failures can be correlated per account without
writing personal data into log storage (GDPR data minimisation).
"""

from __future__ import annotations

import hashlib
import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any

_RESERVED = set(vars(logging.makeLogRecord({})))


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        payload.update({k: v for k, v in vars(record).items() if k not in _RESERVED})
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)


security_log = logging.getLogger("security")


def fingerprint(value: str) -> str:
    return hashlib.sha256(value.strip().lower().encode()).hexdigest()[:16]


def security_event(event: str, **fields: Any) -> None:
    security_log.warning(event, extra={"event": event, **fields})
