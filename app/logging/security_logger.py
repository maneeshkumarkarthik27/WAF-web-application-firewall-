from __future__ import annotations

import json
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from app.models.security import SecurityAssessment


class SecurityLogger:
    def __init__(self, log_dir: str = "logs") -> None:
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger("waf.security")
        self.logger.setLevel(logging.INFO)
        if not any(isinstance(handler, RotatingFileHandler) for handler in self.logger.handlers):
            handler = RotatingFileHandler(self.log_dir / "security.log", maxBytes=5_000_000, backupCount=5)
            handler.setFormatter(logging.Formatter("%(message)s"))
            self.logger.addHandler(handler)
        self.logger.propagate = False

    def log_assessment(self, assessment: SecurityAssessment) -> None:
        self.logger.info(json.dumps(assessment.to_log_record(), sort_keys=True, default=str))
