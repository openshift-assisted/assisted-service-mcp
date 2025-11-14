import importlib
import sys
import logging
import os

from assisted_service_mcp.src.logger import SensitiveFormatter


def _reload_settings(env: dict[str, str]) -> None:  # type: ignore[no-untyped-def]
    os.environ.update(env)
    mod = "assisted_service_mcp.src.settings"
    if mod in sys.modules:
        del sys.modules[mod]
    importlib.import_module(mod)


def test_configure_logging_stream_only() -> None:
    _reload_settings(
        {
            "LOGGER_NAME": "assisted-mcp-test",
            "LOGGING_LEVEL": "DEBUG",
            "LOG_TO_FILE": "false",
        }
    )

    logger_mod = importlib.import_module("assisted_service_mcp.src.logger")
    logger = logger_mod.configure_logging()

    assert logger.name == "assisted-mcp-test"
    assert logger.level == logging.DEBUG
    # At least one StreamHandler present
    assert any(isinstance(h, logging.StreamHandler) for h in logger.handlers)
    # No FileHandler when LOG_TO_FILE is false
    assert not any(isinstance(h, logging.FileHandler) for h in logger.handlers)


def test_configure_logging_with_file() -> None:
    _reload_settings(
        {
            "LOGGER_NAME": "assisted-mcp-test-file",
            "LOGGING_LEVEL": "INFO",
            "LOG_TO_FILE": "true",
        }
    )

    logger_mod = importlib.import_module("assisted_service_mcp.src.logger")
    logger = logger_mod.configure_logging()

    assert logger.name == "assisted-mcp-test-file"
    assert logger.level == logging.INFO
    assert any(isinstance(h, logging.StreamHandler) for h in logger.handlers)
    assert any(isinstance(h, logging.FileHandler) for h in logger.handlers)


def filter_text(text: str) -> str:
    return SensitiveFormatter._filter(text)  # pylint: disable=protected-access


def test_redact_object_style_single_quotes() -> None:
    original = "pull_secret='abc123' ssh_public_key='ssh-rsa AAA' vsphere_username='user' vsphere_password='pass'"
    redacted = filter_text(original)
    assert "pull_secret='*** PULL_SECRET ***'" in redacted
    assert "ssh_public_key='*** SSH_KEY ***'" in redacted
    assert "vsphere_username='*** VSPHERE_USER ***'" in redacted
    assert "vsphere_password='*** VSPHERE_PASSWORD ***'" in redacted


def test_redact_object_style_double_quotes() -> None:
    original = 'pull_secret="abc123" ssh_public_key="ssh-rsa AAA" vsphere_username="user" vsphere_password="pass"'
    redacted = filter_text(original)
    assert 'pull_secret="*** PULL_SECRET ***"' in redacted
    assert 'ssh_public_key="*** SSH_KEY ***"' in redacted
    assert 'vsphere_username="*** VSPHERE_USER ***"' in redacted
    assert 'vsphere_password="*** VSPHERE_PASSWORD ***"' in redacted


def test_redact_object_style_unquoted() -> None:
    original = "pull_secret=abc123 ssh_public_key=ssh-rsaAAA vsphere_username=user vsphere_password=pass"
    redacted = filter_text(original)
    assert "pull_secret=*** PULL_SECRET ***" in redacted
    assert "ssh_public_key=*** SSH_KEY ***" in redacted
    assert "vsphere_username=*** VSPHERE_USER ***" in redacted
    assert "vsphere_password=*** VSPHERE_PASSWORD ***" in redacted


def test_preserve_spaces_around_equals() -> None:
    original = "pull_secret =  'abc123'  ssh_public_key=\t\t\"k\"  vsphere_username= user vsphere_password =pass"
    redacted = filter_text(original)
    assert "pull_secret =  '*** PULL_SECRET ***'" in redacted
    assert 'ssh_public_key=\t\t"*** SSH_KEY ***"' in redacted
    assert "vsphere_username= *** VSPHERE_USER ***" in redacted
    assert "vsphere_password =*** VSPHERE_PASSWORD ***" in redacted
