"""
Logging utilities with sensitive information filtering.

This module provides logging configuration and formatting utilities that
automatically filter sensitive information like pull secrets, SSH keys,
and vSphere credentials from log messages.
"""

# -*- coding: utf-8 -*-
import logging
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
            r"('_vsphere_username':\s+)'(.*?)'", r"\g<1>'*** VSPHERE USER ***'", s
        )
        s = re.sub(
            r"('_vsphere_password':\s+)'(.*?)'", r"\g<1>'*** VSPHERE PASSWORD ***'", s
        )

        # Object filter
        def _redact_value(text: str, key: str, placeholder: str) -> str:
            # Match quoted (single or double) or unquoted values, preserving spacing and quotes
            pattern = re.compile(
                rf"({re.escape(key)})(\s*=\s*)(?:'([^']*)'|\"([^\"]*)\"|([^\s,}}]+))"
            )

            def _repl(m: re.Match) -> str:
                key_part = m.group(1)
                eq_spaces = m.group(2)
                if m.group(3) is not None:  # single-quoted
                    return f"{key_part}{eq_spaces}'{placeholder}'"
                if m.group(4) is not None:  # double-quoted
                    return f'{key_part}{eq_spaces}"{placeholder}"'
                # unquoted
                return f"{key_part}{eq_spaces}{placeholder}"

            return pattern.sub(_repl, text)

        s = _redact_value(s, "pull_secret", "*** PULL_SECRET ***")
        s = _redact_value(s, "ssh_public_key", "*** SSH_KEY ***")
        s = _redact_value(s, "vsphere_username", "*** VSPHERE_USER ***")
        s = _redact_value(s, "vsphere_password", "*** VSPHERE_PASSWORD ***")

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
    Get the logging level from settings.

    Returns:
        int: The logging level (defaults to INFO if not set or invalid).
    """
    # Import here to avoid circular dependency at module load time
    from assisted_service_mcp.src.settings import settings

    level = settings.LOGGING_LEVEL
    return getattr(logging, str(level).upper(), logging.INFO) if level else logging.INFO


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


# Export a module-level logger with a safe default name to avoid circular imports.
# Configuration should be done by calling configure_logging() after settings are ready.
log = logging.getLogger("assisted-service-mcp")


def configure_logging() -> logging.Logger:
    """
    Configure logging after settings are available.

    This sets logger names/levels, third-party logger levels, and attaches
    file/stream handlers with the SensitiveFormatter. Importing settings here
    avoids circular imports at module load time.

    Returns:
        logging.Logger: The configured application logger.
    """
    # Import inside function to avoid circular dependency
    from assisted_service_mcp.src.settings import settings

    # Resolve logger name, falling back to a stable default
    logger_name = settings.LOGGER_NAME or "assisted-service-mcp"
    target_logger = logging.getLogger(logger_name)

    # Configure third-party loggers
    logging.getLogger("requests").setLevel(logging.ERROR)
    urllib3_logger = logging.getLogger("urllib3")

    # Reset handlers to prevent duplicates on reconfiguration
    for handler in target_logger.handlers:
        handler.close()
    target_logger.handlers = []
    for handler in urllib3_logger.handlers:
        handler.close()
    urllib3_logger.handlers = []

    # Set levels
    urllib3_logger.setLevel(logging.ERROR)
    target_logger.setLevel(get_logging_level())

    # Optional file logging
    if settings.LOG_TO_FILE:
        add_log_file_handler(target_logger, "assisted-service-mcp.log")
        add_log_file_handler(urllib3_logger, "assisted-service-mcp.log")

    # Always add stream handlers
    add_stream_handler(target_logger)
    add_stream_handler(urllib3_logger)

    # Ensure modules using `from ...logger import log` get the configured logger
    global log  # pylint: disable=global-statement
    log = target_logger
    return target_logger
