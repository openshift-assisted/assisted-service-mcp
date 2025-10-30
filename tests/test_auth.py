import types
import importlib
from unittest.mock import Mock, patch, MagicMock
import requests

import pytest

from assisted_service_mcp.utils import auth as auth_mod


class _ReqCtx:
    def __init__(self, headers: dict[str, str] | None) -> None:
        self.request_context = types.SimpleNamespace(
            request=(
                types.SimpleNamespace(headers=headers) if headers is not None else None
            )
        )


class _MCP:
    def __init__(self, headers: dict[str, str] | None) -> None:
        self._ctx = _ReqCtx(headers)

    def get_context(self) -> object:  # noqa: D401
        return self._ctx


def test_get_offline_token_prefers_settings_env() -> None:
    with patch("assisted_service_mcp.src.settings.settings.OFFLINE_TOKEN", "env-token"):
        mcp = _MCP(headers={"OCM-Offline-Token": "header-token"})
        assert auth_mod.get_offline_token(mcp) == "env-token"


def test_get_offline_token_from_header_when_no_env() -> None:
    with patch("assisted_service_mcp.src.settings.settings.OFFLINE_TOKEN", None):
        mcp = _MCP(headers={"OCM-Offline-Token": "header-token"})
        assert auth_mod.get_offline_token(mcp) == "header-token"


def test_get_offline_token_raises_when_missing() -> None:
    with patch("assisted_service_mcp.src.settings.settings.OFFLINE_TOKEN", None):
        mcp = _MCP(headers={})
        with pytest.raises(RuntimeError):
            auth_mod.get_offline_token(mcp)


def test_get_access_token_from_authorization_header() -> None:
    mcp = _MCP(headers={"Authorization": "Bearer abc"})
    assert auth_mod.get_access_token(mcp) == "abc"


@patch("requests.post")
def test_get_access_token_via_offline_token(mock_post: Mock) -> None:  # type: ignore[no-untyped-def]
    mcp = _MCP(headers={})

    with (
        patch("assisted_service_mcp.src.settings.settings.OFFLINE_TOKEN", "offline"),
        patch(
            "assisted_service_mcp.src.settings.settings.SSO_URL", "https://sso/token"
        ),
    ):
        mock_resp = Mock()
        mock_resp.json.return_value = {"access_token": "new-token"}
        mock_post.return_value = mock_resp

        token = auth_mod.get_access_token(mcp)
        assert token == "new-token"
        mock_post.assert_called_once()


def test_get_access_token_sso_request_exception() -> None:
    mod = importlib.import_module("assisted_service_mcp.utils.auth")
    mcp = MagicMock()
    mcp.get_context.return_value = MagicMock(request_context=None)

    with (
        patch("assisted_service_mcp.utils.auth.requests.post") as mock_post,
        patch(
            "assisted_service_mcp.utils.auth.get_setting",
            side_effect=lambda k: "https://sso.example.com" if k == "SSO_URL" else "",
        ),
    ):
        mock_post.side_effect = requests.exceptions.RequestException("network error")
        with pytest.raises(
            RuntimeError, match="Failed to obtain access token from SSO"
        ):
            mod.get_access_token(mcp, offline_token_func=lambda: "offline")


def test_get_access_token_invalid_json_response() -> None:
    mod = importlib.import_module("assisted_service_mcp.utils.auth")
    mcp = MagicMock()
    mcp.get_context.return_value = MagicMock(request_context=None)

    mock_resp = MagicMock()
    mock_resp.raise_for_status.return_value = None
    mock_resp.json.return_value = {}

    with (
        patch("assisted_service_mcp.utils.auth.requests.post", return_value=mock_resp),
        patch(
            "assisted_service_mcp.utils.auth.get_setting",
            side_effect=lambda k: "https://sso.example.com" if k == "SSO_URL" else "",
        ),
    ):
        with pytest.raises(RuntimeError, match="Invalid SSO response"):
            mod.get_access_token(mcp, offline_token_func=lambda: "offline")
