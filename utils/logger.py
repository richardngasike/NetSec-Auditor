"""
Centralized logging configuration.
"""

import logging
import sys
from pathlib import Path


_LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
_configured = False


def configure_logging(verbose: bool = False, log_file: str = None):
    global _configured
    level = logging.DEBUG if verbose else logging.WARNING
    handlers = [logging.StreamHandler(sys.stderr)]

    if log_file:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(log_file))

    logging.basicConfig(level=level, format=_LOG_FORMAT, datefmt=_DATE_FORMAT, handlers=handlers)
    _configured = True


def get_logger(name: str) -> logging.Logger:
    if not _configured:
        configure_logging()
    return logging.getLogger(name)
