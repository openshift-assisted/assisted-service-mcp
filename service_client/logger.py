"""
Logging utilities with sensitive information filtering.

This module provides logging configuration and formatting utilities that
automatically filter sensitive information like pull secrets, SSH keys,
and vSphere credentials from log messages.
"""

# -*- coding: utf-8 -*-
import logging
import os
import re
import sys
import atexit
import queue
from logging.handlers import QueueHandler, QueueListener


class SensitiveFormatter(logging.Formatter):
    """Formatter that removes sensitive info."""

    # Default log format used by this formatter
    DEFAULT_FORMAT = "%(asctime)s - %(name)s - %(levelname)-8s - %(thread)d:%(process)d - %(message)s - (%(pathname)s:%(lineno)d)->%(funcName)s"

    def __init__(self, fmt: str | None = None) -> None:
        """Initialize with default format if none provided."""
        if fmt is None:
            fmt = self.DEFAULT_FORMAT
        super().__init__(fmt)

    @staticmethod
    def _filter(s: str) -> str:
        # Dict filter
        s = re.sub(r"('_pull_secret':\s+)'(.*?)'", r"\g<1>'*** PULL_SECRET ***'", s)
        s = re.sub(r"('_ssh_public_key':\s+)'(.*?)'", r"\g<1>'*** SSH_KEY ***'", s)
        s = re.sub(
            r"('_vsphere_username':\s+)'(.*?)'", r"\g<1>'*** VSPHERE_USER ***'", s
        )
        s = re.sub(
            r"('_vsphere_password':\s+)'(.*?)'", r"\g<1>'*** VSPHERE_PASSWORD ***'", s
        )

        # Object filter
        s = re.sub(
            r"(pull_secret='[^']*(?=')')", "pull_secret = *** PULL_SECRET ***", s
        )
        s = re.sub(
            r"(ssh_public_key='[^']*(?=')')", "ssh_public_key = *** SSH_KEY ***", s
        )
        s = re.sub(
            r"(vsphere_username='[^']*(?=')')",
            "vsphere_username = *** VSPHERE_USER ***",
            s,
        )
        s = re.sub(
            r"(vsphere_password='[^']*(?=')')",
            "vsphere_password = *** VSPHERE_PASSWORD ***",
            s,
        )

        return s

    def format(self, record: logging.LogRecord) -> str:
        """
        Format log record while filtering sensitive information.

        Args:
            record: The LogRecord instance to be formatted.

        Returns:
            str: The formatted log message with sensitive info redacted.
        """
        original = logging.Formatter.format(self, record)
        return self._filter(original)


def get_logging_level() -> int:
    """
    Get the logging level from environment variable.

    Returns:
        int: The logging level (defaults to INFO if not set or invalid).
    """
    level = os.environ.get("LOGGING_LEVEL", "")
    return getattr(logging, level.upper(), logging.INFO) if level else logging.INFO


logging.getLogger("requests").setLevel(logging.ERROR)
logging.getLogger("urllib3").setLevel(logging.ERROR)
logging.getLogger("asyncio").setLevel(logging.ERROR)


def _create_file_handler(filename: str) -> logging.FileHandler:
    """Create a file handler with sensitive formatting."""
    fh = logging.FileHandler(filename)
    fh.setFormatter(SensitiveFormatter())
    return fh


def _create_stream_handler() -> logging.StreamHandler:
    """Create a stream handler to stderr with sensitive formatting."""
    ch = logging.StreamHandler(sys.stderr)
    ch.setFormatter(SensitiveFormatter())
    return ch


logger_name = os.environ.get("LOGGER_NAME", "")
urllib3_logger = logging.getLogger("urllib3")
urllib3_logger.handlers = [logging.NullHandler()]

logging.getLogger("requests").setLevel(logging.ERROR)
urllib3_logger.setLevel(logging.ERROR)

log = logging.getLogger(logger_name)
log.setLevel(get_logging_level())

# Check if we should log to file (default: True, set to False in containers)
log_to_file = os.environ.get("LOG_TO_FILE", "true").lower() == "true"

# Configure non-blocking logging via a Queue
_log_queue: queue.Queue[logging.LogRecord] = queue.Queue()

_handlers: list[logging.Handler] = []
if log_to_file:
    _handlers.append(_create_file_handler("assisted-service-mcp.log"))
_handlers.append(_create_stream_handler())

# Start a single listener that will process records on a background thread
_queue_listener = QueueListener(_log_queue, *_handlers, respect_handler_level=True)
_queue_listener.start()

# Attach QueueHandler to our loggers
_queue_handler = QueueHandler(_log_queue)

# Avoid duplicate propagation if root logger is used
log.handlers = [_queue_handler] if _queue_handler not in log.handlers else []
log.propagate = False

urllib3_logger.handlers = (
    [_queue_handler] if _queue_handler not in urllib3_logger.handlers else []
)
urllib3_logger.propagate = False


def _stop_queue_listener() -> None:
    try:
        _queue_listener.stop()
    except Exception:  # noqa: BLE001 - best effort stop at exit
        pass


atexit.register(_stop_queue_listener)
