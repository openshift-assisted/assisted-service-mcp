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


def add_log_file_handler(logger: logging.Logger, filename: str) -> logging.FileHandler:
    """
    Add a file handler to the logger with sensitive information filtering.

    Args:
        logger: The logger instance to add the handler to.
        filename: The path to the log file.

    Returns:
        logging.FileHandler: The created file handler.
    """
    fh = logging.FileHandler(filename)
    fh.setFormatter(SensitiveFormatter())
    logger.addHandler(fh)
    return fh


def add_stream_handler(logger: logging.Logger) -> None:
    """
    Add a stream handler to the logger with sensitive information filtering.

    Args:
        logger: The logger instance to add the handler to.
    """
    ch = logging.StreamHandler(sys.stderr)
    ch.setFormatter(SensitiveFormatter())
    logger.addHandler(ch)


logger_name = os.environ.get("LOGGER_NAME", "")
urllib3_logger = logging.getLogger("urllib3")
urllib3_logger.handlers = [logging.NullHandler()]

logging.getLogger("requests").setLevel(logging.ERROR)
urllib3_logger.setLevel(logging.ERROR)

log = logging.getLogger(logger_name)
log.setLevel(get_logging_level())

# Check if we should log to file (default: True, set to False in containers)
log_to_file = os.environ.get("LOG_TO_FILE", "true").lower() == "true"

if log_to_file:
    add_log_file_handler(log, "assisted-service-mcp.log")
    add_log_file_handler(urllib3_logger, "assisted-service-mcp.log")

add_stream_handler(log)
add_stream_handler(urllib3_logger)
