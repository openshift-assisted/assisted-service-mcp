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


def test_redact_authorization_bearer_token() -> None:
    original = 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
    redacted = filter_text(original)
    assert "Authorization: Bearer *** TOKEN ***" in redacted


def test_redact_authorization_bearer_token_case_insensitive() -> None:
    original = 'authorization: bearer abc123xyz'
    redacted = filter_text(original)
    assert "*** TOKEN ***" in redacted
    assert "abc123xyz" not in redacted


def test_redact_authorization_bearer_token_with_quotes() -> None:
    original = '"Authorization": "Bearer token_value_here"'
    redacted = filter_text(original)
    assert "*** TOKEN ***" in redacted
    assert "token_value_here" not in redacted


def test_redact_x_amz_signature() -> None:
    original = "X-Amz-Signature=abcdef1234567890ABCDEF"
    redacted = filter_text(original)
    assert "X-Amz-Signature=*** REDACTED ***" in redacted
    assert "abcdef1234567890ABCDEF" not in redacted


def test_redact_json_pull_secret() -> None:
    original = '{"pull_secret": "super-secret-value", "other": "data"}'
    redacted = filter_text(original)
    assert '"pull_secret": "*** REDACTED ***"' in redacted
    assert "super-secret-value" not in redacted


def test_redact_json_ssh_public_key() -> None:
    original = '{"ssh_public_key": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...", "other": "data"}'
    redacted = filter_text(original)
    assert '"ssh_public_key": "*** REDACTED ***"' in redacted
    assert "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC" not in redacted


def test_redact_json_pull_secret_with_spaces() -> None:
    original = '{ "pull_secret"  :  "value-here" }'
    redacted = filter_text(original)
    assert '"pull_secret"' in redacted
    assert "*** REDACTED ***" in redacted
    assert "value-here" not in redacted


def test_redact_bearer_token_with_base64url_chars() -> None:
    """Test that Bearer tokens with +, /, ~, = are fully redacted."""
    # Token with plus and slash (base64url encoding)
    original = 'Authorization: Bearer abc+DEF/123='
    redacted = filter_text(original)
    assert "Authorization: Bearer *** TOKEN ***" in redacted
    assert "abc+DEF/123=" not in redacted
    assert "+" not in redacted
    assert "/" not in redacted

    # Token with tilde
    original = 'Authorization: Bearer token~with~tildes'
    redacted = filter_text(original)
    assert "*** TOKEN ***" in redacted
    assert "token~with~tildes" not in redacted


def test_redact_bare_bearer_token() -> None:
    """Test that bare Bearer tokens without Authorization header are redacted."""
    # Bare Bearer in log message
    original = 'Request failed with Bearer eyJhbGc+iJIUzI1/NiIsInR5cCI='
    redacted = filter_text(original)
    assert "Bearer *** TOKEN ***" in redacted
    assert "eyJhbGc+iJIUzI1/NiIsInR5cCI=" not in redacted

    # Bearer in debug output
    original = 'Debug: token is Bearer abc+123/xyz='
    redacted = filter_text(original)
    assert "Bearer *** TOKEN ***" in redacted
    assert "abc+123/xyz=" not in redacted


def test_redact_bearer_token_case_insensitive_with_special_chars() -> None:
    """Test case-insensitive Bearer redaction with special characters."""
    original = 'bearer abc+DEF/123='
    redacted = filter_text(original)
    assert "bearer *** TOKEN ***" in redacted
    assert "abc+DEF/123=" not in redacted


def test_redact_x_amz_security_token() -> None:
    """Test that X-Amz-Security-Token (AWS session tokens) are redacted."""
    original = "X-Amz-Security-Token=FQoDYXdzEPT%2F%2FwEaDEMkL5C%2BnZmvgFiuziK3A9OQ"
    redacted = filter_text(original)
    assert "X-Amz-Security-Token=*** REDACTED ***" in redacted
    assert "FQoDYXdzEPT" not in redacted


def test_redact_x_amz_credential() -> None:
    """Test that X-Amz-Credential (AWS access key material) is redacted."""
    original = "X-Amz-Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request"
    redacted = filter_text(original)
    assert "X-Amz-Credential=*** REDACTED ***" in redacted
    assert "AKIAIOSFODNN7EXAMPLE" not in redacted


def test_redact_full_presigned_url() -> None:
    """Test redaction of a complete AWS presigned URL with all credentials."""
    original = (
        "https://s3.amazonaws.com/bucket/file?"
        "X-Amz-Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request&"
        "X-Amz-Signature=34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7&"
        "X-Amz-Security-Token=FQoDYXdzEPT%2F%2FwEaDEMkL5C%2BnZmvgFiuziK3A9OQ"
    )
    redacted = filter_text(original)
    # All three credential components should be redacted
    assert "X-Amz-Credential=*** REDACTED ***" in redacted
    assert "X-Amz-Signature=*** REDACTED ***" in redacted
    assert "X-Amz-Security-Token=*** REDACTED ***" in redacted
    # Verify actual values are gone
    assert "AKIAIOSFODNN7EXAMPLE" not in redacted
    assert "34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7" not in redacted
    assert "FQoDYXdzEPT" not in redacted
