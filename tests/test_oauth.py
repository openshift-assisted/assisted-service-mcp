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
from assisted_service_mcp.src.oauth.manager import DEFAULT_TOKEN_EXPIRES_IN
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

    @patch("httpx.AsyncClient")
    async def test_refresh_token_success(self, mock_client_class: MagicMock) -> None:
        """Test successful token refresh."""
        import time

        from assisted_service_mcp.src.oauth.models import OAuthToken

        # Create an expired token with refresh token
        expired_token = OAuthToken(
            token_id="test_token_id",
            client_id="test_client",
            access_token="old_access_token",
            refresh_token="test_refresh_token",
            expires_at=time.time() - 3600,  # Expired 1 hour ago
            token_type="Bearer",
        )

        # Store the expired token
        self.oauth_manager.token_store.store_token(expired_token)

        # Mock successful refresh response
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "access_token": "new_access_token",
            "token_type": "Bearer",
            "expires_in": DEFAULT_TOKEN_EXPIRES_IN,
            "refresh_token": "new_refresh_token",
        }
        mock_response.raise_for_status.return_value = None

        # Mock the async client
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_client_class.return_value = mock_client

        # Call refresh
        result = await self.oauth_manager.get_access_token_by_client("test_client")

        # Verify refresh was successful
        assert result == "new_access_token"
        mock_client.post.assert_called_once()

        # Verify token was updated in store
        updated_token = self.oauth_manager.token_store.get_token_by_id("test_token_id")
        assert updated_token is not None
        assert updated_token.access_token == "new_access_token"
        assert updated_token.refresh_token == "new_refresh_token"
        assert not updated_token.is_expired()

    async def test_refresh_token_no_refresh_token(self) -> None:
        """Test refresh fails when no refresh token available."""
        import time

        from assisted_service_mcp.src.oauth.models import OAuthToken

        # Create an expired token without refresh token
        expired_token = OAuthToken(
            token_id="test_token_id",
            client_id="test_client",
            access_token="old_access_token",
            refresh_token=None,  # No refresh token
            expires_at=time.time() - 10 * 60,  # 10 minutes ago
            token_type="Bearer",
        )

        # Store the expired token
        self.oauth_manager.token_store.store_token(expired_token)

        # Call refresh - should return None
        result = await self.oauth_manager.get_access_token_by_client("test_client")

        # Verify refresh failed
        assert result is None
        # Verify token was cleaned up
        assert self.oauth_manager.token_store.get_token_by_id("test_token_id") is None

    @patch("httpx.AsyncClient")
    async def test_refresh_token_api_error(self, mock_client_class: MagicMock) -> None:
        """Test refresh fails when API returns error."""
        import time

        from assisted_service_mcp.src.oauth.models import OAuthToken

        # Create an expired token with refresh token
        expired_token = OAuthToken(
            token_id="test_token_id",
            client_id="test_client",
            access_token="old_access_token",
            refresh_token="test_refresh_token",
            expires_at=time.time() - DEFAULT_TOKEN_EXPIRES_IN,
            token_type="Bearer",
        )

        # Store the expired token
        self.oauth_manager.token_store.store_token(expired_token)

        # Mock API error response
        mock_response = MagicMock()
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Bad Request", request=MagicMock(), response=MagicMock()
        )

        # Mock the async client
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_client_class.return_value = mock_client

        # Call refresh - should return None
        result = await self.oauth_manager.get_access_token_by_client("test_client")

        # Verify refresh failed
        assert result is None
        # Verify token was cleaned up
        assert self.oauth_manager.token_store.get_token_by_id("test_token_id") is None

    async def test_get_access_token_by_client_valid_token(self) -> None:
        """Test getting access token when token is still valid."""
        import time

        from assisted_service_mcp.src.oauth.models import OAuthToken

        # Create a valid token
        valid_token = OAuthToken(
            token_id="test_token_id",
            client_id="test_client",
            access_token="valid_access_token",
            refresh_token="test_refresh_token",
            expires_at=time.time() + 3600,  # Valid for 1 hour
            token_type="Bearer",
        )

        # Store the token
        self.oauth_manager.token_store.store_token(valid_token)

        # Get token - should not trigger refresh
        result = await self.oauth_manager.get_access_token_by_client("test_client")

        # Verify we got the valid token without refresh
        assert result == "valid_access_token"


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


class TestMCPOAuthTokenExpiry:  # pylint: disable=protected-access
    """Test cases for MCP OAuth token expiry handling."""

    @patch("assisted_service_mcp.src.mcp.settings.OAUTH_ENABLED", True)
    @patch("asyncio.run")
    def test_expired_token_triggers_refresh(self, mock_asyncio_run: MagicMock) -> None:
        """Test that expired token triggers refresh flow."""
        # Mock the MCP server and its methods
        mock_mcp = MagicMock()
        mock_mcp.get_context.return_value = MagicMock(request_context=None)

        # Import and create server instance
        from assisted_service_mcp.src.mcp import AssistedServiceMCPServer

        server = AssistedServiceMCPServer()

        # Mock the oauth imports
        with (
            patch(
                "assisted_service_mcp.src.oauth.get_oauth_access_token_from_mcp",
                return_value=None,
            ),
            patch(
                "assisted_service_mcp.src.oauth.mcp_oauth_middleware.pending_auth_sessions",
                {},
            ),
        ):
            # Mock asyncio.run to return refreshed token
            # This simulates oauth_manager.get_access_token_by_client() successfully refreshing
            mock_asyncio_run.return_value = "refreshed_access_token"

            # Call the oauth token function
            result = server._get_oauth_token(
                mock_mcp
            )  # pylint: disable=protected-access

            # Verify async method was called (which handles refresh)
            mock_asyncio_run.assert_called_once()
            # Verify we got the refreshed token
            assert result == "refreshed_access_token"

    @patch("assisted_service_mcp.src.mcp.settings.OAUTH_ENABLED", True)
    def test_valid_token_returned_without_refresh(self) -> None:
        """Test that valid token is returned without triggering refresh."""
        # Mock the MCP server and its methods
        mock_mcp = MagicMock()
        mock_mcp.get_context.return_value = MagicMock(request_context=None)

        # Import and create server instance
        from assisted_service_mcp.src.mcp import AssistedServiceMCPServer

        server = AssistedServiceMCPServer()

        # Mock the oauth imports
        with (
            patch(
                "assisted_service_mcp.src.oauth.get_oauth_access_token_from_mcp",
                return_value=None,
            ),
            patch("asyncio.run") as mock_asyncio_run,
        ):
            # Mock asyncio.run to return the valid token (simulating async get_access_token_by_client)
            mock_asyncio_run.return_value = "valid_access_token"

            # Call the oauth token function
            result = server._get_oauth_token(
                mock_mcp
            )  # pylint: disable=protected-access

            # Verify async method was called (which handles token retrieval and refresh)
            mock_asyncio_run.assert_called_once()
            assert result == "valid_access_token"

    @patch("assisted_service_mcp.src.mcp.settings.OAUTH_ENABLED", True)
    @patch("asyncio.run")
    def test_expired_token_refresh_failure_starts_new_flow(
        self, mock_asyncio_run: MagicMock
    ) -> None:
        """Test that failed refresh triggers new OAuth flow."""
        # Mock the MCP server
        mock_mcp = MagicMock()
        mock_mcp.get_context.return_value = MagicMock(request_context=None)

        # Import and create server instance
        from assisted_service_mcp.src.mcp import AssistedServiceMCPServer

        server = AssistedServiceMCPServer()

        # Mock refresh to fail (oauth_manager.get_access_token_by_client returns None or raises)
        # This simulates refresh failing, so get_access_token_by_client returns None
        mock_asyncio_run.return_value = None

        # Mock the oauth imports
        with (
            patch(
                "assisted_service_mcp.src.oauth.get_oauth_access_token_from_mcp",
                return_value=None,
            ),
            patch(
                "assisted_service_mcp.src.oauth.mcp_oauth_middleware.pending_auth_sessions",
                {},
            ),
            patch(
                "assisted_service_mcp.src.oauth.oauth_manager.create_authorization_url",
                return_value=(
                    "https://oauth.example.com/auth",
                    '{"session_id": "test_session", "client_id": "test_client", "timestamp": 123456, "code_verifier": "test_verifier"}',
                ),
            ),
            patch("assisted_service_mcp.src.oauth.open_browser_for_oauth"),
        ):
            # Call should raise RuntimeError for new OAuth flow
            with pytest.raises(RuntimeError, match="OAuth authentication required"):
                server._get_oauth_token(mock_mcp)  # pylint: disable=protected-access

            # Verify async method was called (attempted refresh)
            mock_asyncio_run.assert_called_once()
