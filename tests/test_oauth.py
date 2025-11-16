"""Tests for OAuth authentication functionality."""

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from fastapi import HTTPException

from assisted_service_mcp.src.oauth import (
    OAuthManager,
    oauth_callback_handler,
    oauth_register_handler,
    oauth_token_handler,
    get_oauth_access_token_from_mcp,
)
from assisted_service_mcp.src.settings import settings


class TestOAuthManager:
    """Test cases for OAuthManager class."""

    oauth_manager: OAuthManager

    def setup_method(self) -> None:
        """Set up test fixtures."""
        self.oauth_manager = OAuthManager()

    @patch("httpx.AsyncClient")
    async def test_exchange_code_for_token_success(
        self, mock_client_class: MagicMock
    ) -> None:
        """Test successful code exchange for token."""
        # Setup
        state = "test_state"
        code = "test_code"

        # Generate state first to store PKCE verifier
        self.oauth_manager.get_authorization_url(state)

        # Mock successful response
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "access_token": "test_access_token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "test_refresh_token",
        }
        mock_response.raise_for_status.return_value = None

        # Mock the async client
        mock_client = MagicMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client_class.return_value = mock_client

        # Execute
        token = await self.oauth_manager.exchange_code_for_token(code, state)

        # Verify
        assert token is not None
        assert token["access_token"] == "test_access_token"
        assert token["token_type"] == "Bearer"
        mock_client.post.assert_called_once()

    @patch("httpx.AsyncClient")
    async def test_exchange_code_for_token_request_failure(
        self, mock_client_class: MagicMock
    ) -> None:
        """Test code exchange with request failure."""
        # Setup
        state = "test_state"
        code = "test_code"

        # Generate state first
        self.oauth_manager.get_authorization_url(state)

        # Mock request failure
        mock_client = MagicMock()
        mock_client.post = AsyncMock(side_effect=httpx.HTTPError("Network error"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client_class.return_value = mock_client

        # Execute and verify
        with pytest.raises(HTTPException) as exc_info:
            await self.oauth_manager.exchange_code_for_token(code, state)

        assert exc_info.value.status_code == 400


class TestOAuthHandlers:
    """Test cases for OAuth HTTP handlers."""

    async def test_oauth_register_handler_success(self) -> None:
        """Test successful OAuth registration."""
        mock_request = MagicMock()

        with patch("assisted_service_mcp.src.oauth.settings.OAUTH_ENABLED", True):
            response = await oauth_register_handler(mock_request)

        assert "authorization_endpoint" in response
        assert "token_endpoint" in response
        assert "client_id" in response
        assert "redirect_uri" in response
        assert "state" in response
        assert response["client_id"] == settings.OAUTH_CLIENT

    async def test_oauth_callback_handler_success(self) -> None:
        """Test successful OAuth callback."""
        mock_request = MagicMock()
        # Create a proper mock query_params object
        mock_query_params = MagicMock()
        mock_query_params.get.side_effect = lambda key, default=None: {
            "code": "test_code",
            "state": "test_state",
        }.get(key, default)
        mock_request.query_params = mock_query_params

        with (
            patch("assisted_service_mcp.src.oauth.settings.OAUTH_ENABLED", True),
            patch(
                "assisted_service_mcp.src.oauth.oauth_manager.exchange_code_for_token"
            ) as mock_exchange,
        ):
            mock_exchange.return_value = {"access_token": "test_token"}

            response = await oauth_callback_handler(mock_request)

            assert response.status_code == 200
            assert "Authentication Successful!" in bytes(response.body).decode()

    async def test_oauth_callback_handler_error(self) -> None:
        """Test OAuth callback with error."""
        mock_request = MagicMock()
        # Create a proper mock query_params object
        mock_query_params = MagicMock()
        mock_query_params.get.side_effect = lambda key, default=None: {
            "error": "access_denied"
        }.get(key, default)
        mock_request.query_params = mock_query_params

        with patch("assisted_service_mcp.src.oauth.settings.OAUTH_ENABLED", True):
            response = await oauth_callback_handler(mock_request)

        assert response.status_code == 400
        assert "OAuth Authentication Failed" in bytes(response.body).decode()

    async def test_oauth_token_handler_success(self) -> None:
        """Test successful OAuth token exchange."""
        mock_request = MagicMock()
        mock_request.headers = {"content-type": "application/json"}
        mock_request.json = AsyncMock(
            return_value={
                "grant_type": "authorization_code",
                "code": "test_code",
                "state": "test_state",
            }
        )

        with (
            patch("assisted_service_mcp.src.oauth.settings.OAUTH_ENABLED", True),
            patch(
                "assisted_service_mcp.src.oauth.oauth_manager.exchange_code_for_token"
            ) as mock_exchange,
        ):
            mock_exchange.return_value = {
                "access_token": "test_token",
                "token_type": "Bearer",
                "expires_in": 3600,
            }

            response = await oauth_token_handler(mock_request)

            assert response["access_token"] == "test_token"
            assert response["token_type"] == "Bearer"


class TestOAuthIntegration:
    """Test cases for OAuth integration with MCP."""

    def test_get_oauth_access_token_from_mcp_with_token_id(self) -> None:
        """Test getting OAuth token from MCP with token ID header."""
        from assisted_service_mcp.src.oauth.models import OAuthToken
        import time

        mock_mcp = MagicMock()
        mock_context = MagicMock()
        mock_request = MagicMock()

        # Create a proper mock headers object
        mock_headers = MagicMock()
        mock_headers.get.side_effect = lambda key, default=None: {
            "X-OAuth-Token-ID": "test_token_id",
            "Authorization": None,
        }.get(key, default)
        mock_request.headers = mock_headers
        mock_context.request_context.request = mock_request
        mock_mcp.get_context.return_value = mock_context

        # Create a mock token
        mock_token = OAuthToken(
            token_id="test_token_id",
            client_id="test_client",
            access_token="stored_access_token",
            refresh_token=None,
            expires_at=time.time() + 3600,  # Not expired
        )

        with (
            patch("assisted_service_mcp.src.oauth.settings.OAUTH_ENABLED", True),
            patch(
                "assisted_service_mcp.src.oauth.oauth_manager.token_store.get_token_by_id"
            ) as mock_get_token,
        ):
            mock_get_token.return_value = mock_token

            token = get_oauth_access_token_from_mcp(mock_mcp)

            assert token == "stored_access_token"
            mock_get_token.assert_called_once_with("test_token_id")

    def test_get_oauth_access_token_from_mcp_with_bearer_token(self) -> None:
        """Test getting OAuth token from MCP with Bearer token."""
        mock_mcp = MagicMock()
        mock_context = MagicMock()
        mock_request = MagicMock()

        # Create a proper mock headers object
        mock_headers = MagicMock()
        mock_headers.get.side_effect = lambda key, default=None: {
            "X-OAuth-Token-ID": None,
            "Authorization": "Bearer test_bearer_token",
        }.get(key, default)
        mock_request.headers = mock_headers
        mock_context.request_context.request = mock_request
        mock_mcp.get_context.return_value = mock_context

        with patch("assisted_service_mcp.src.oauth.settings.OAUTH_ENABLED", True):
            token = get_oauth_access_token_from_mcp(mock_mcp)

        assert token == "test_bearer_token"

    @patch("assisted_service_mcp.src.settings.settings.OAUTH_ENABLED", False)
    def test_get_oauth_access_token_from_mcp_disabled(self) -> None:
        """Test getting OAuth token when OAuth is disabled."""
        mock_mcp = MagicMock()

        token = get_oauth_access_token_from_mcp(mock_mcp)

        assert token is None

    def test_get_oauth_access_token_from_mcp_no_context(self) -> None:
        """Test getting OAuth token with no MCP context."""
        mock_mcp = MagicMock()
        mock_mcp.get_context.return_value = None

        token = get_oauth_access_token_from_mcp(mock_mcp)

        assert token is None
