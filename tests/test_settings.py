import importlib
import sys
import pytest


def reload_settings_with_env(env: dict[str, str]):  # type: ignore[no-untyped-def]
    module_name = "assisted_service_mcp.src.settings"
    if module_name in sys.modules:
        importlib.reload(importlib.import_module(module_name))
    with pytest.MonkeyPatch().context() as mp:
        for k, v in env.items():
            mp.setenv(k, v)
        # Re-import to apply env overrides
        settings_mod = importlib.import_module(module_name)
        importlib.reload(settings_mod)
        return settings_mod.settings


def test_settings_defaults() -> None:
    settings = reload_settings_with_env({})
    assert settings.MCP_HOST == "0.0.0.0"
    assert settings.MCP_PORT == 8000
    assert settings.TRANSPORT in {"sse", "streamable-http"}
    assert settings.INVENTORY_URL.endswith("/api/assisted-install/v2")
    assert settings.PULL_SECRET_URL.endswith("/api/accounts_mgmt/v1/access_token")
    assert settings.CLIENT_DEBUG is False
    assert settings.SSO_URL.startswith("https://")


def test_settings_env_overrides() -> None:
    settings = reload_settings_with_env(
        {
            "MCP_HOST": "127.0.0.1",
            "MCP_PORT": "9000",
            "TRANSPORT": "streamable-http",
            "INVENTORY_URL": "https://custom.example.com/v2",
            "CLIENT_DEBUG": "true",
        }
    )
    assert settings.MCP_HOST == "127.0.0.1"
    assert settings.MCP_PORT == 9000
    assert settings.TRANSPORT == "streamable-http"
    assert settings.INVENTORY_URL == "https://custom.example.com/v2"
    assert settings.CLIENT_DEBUG is True


def test_logging_level_case_insensitive() -> None:
    # lower-case should be accepted and normalized to upper-case
    settings = reload_settings_with_env({"LOGGING_LEVEL": "debug"})
    assert settings.LOGGING_LEVEL == "DEBUG"


def test_settings_validation_invalid_transport() -> None:
    from pydantic import ValidationError  # pylint: disable=import-outside-toplevel

    with pytest.raises(
        ValidationError, match="Input should be 'sse' or 'streamable-http'"
    ):
        _settings = reload_settings_with_env({"TRANSPORT": "invalid"})


def test_validate_config_invalid_port_low() -> None:
    with pytest.raises(Exception):
        reload_settings_with_env({"MCP_PORT": "1023"})


def test_validate_config_invalid_port_high() -> None:
    with pytest.raises(Exception):
        reload_settings_with_env({"MCP_PORT": "70000"})


def test_validate_config_invalid_log_level() -> None:
    with pytest.raises(Exception):
        reload_settings_with_env({"LOGGING_LEVEL": "VERBOSE"})


def test_validate_config_invalid_transport() -> None:
    with pytest.raises(Exception):
        reload_settings_with_env({"TRANSPORT": "http2"})
