"""Integration tests for OAuth functionality with FastAPI."""

# pylint: disable=redefined-outer-name

from typing import Generator
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response


@pytest.fixture
def oauth_enabled_app() -> Generator[Starlette, None, None]:
    """Create a test app with OAuth enabled."""
    with patch("assisted_service_mcp.src.oauth.settings.OAUTH_ENABLED", True):
        # Create a fresh app instance and manually register OAuth routes
        app = Starlette()

        # Import OAuth handlers
        from assisted_service_mcp.src.oauth import (
            oauth_register_handler,
            oauth_callback_handler,
            oauth_token_handler,
        )

        # Wrap handlers to return proper Response objects
        async def wrapped_register_handler(request: Request) -> Response:
            result = await oauth_register_handler(request)
            if isinstance(result, dict):
                return JSONResponse(result)
            return result

        async def wrapped_callback_handler(request: Request) -> Response:
            result = await oauth_callback_handler(request)
            if isinstance(result, dict):
                return JSONResponse(result)
            return result

        async def wrapped_token_handler(request: Request) -> Response:
            result = await oauth_token_handler(request)
            if isinstance(result, dict):
                return JSONResponse(result)
            return result

        # Register OAuth routes
        app.add_route("/oauth/register", wrapped_register_handler, methods=["GET"])
        app.add_route("/oauth/callback", wrapped_callback_handler, methods=["GET"])
        app.add_route("/oauth/token", wrapped_token_handler, methods=["POST"])

        yield app


@pytest.fixture
def oauth_disabled_app() -> Generator[Starlette, None, None]:
    """Create a test app with OAuth disabled."""
    with patch("assisted_service_mcp.src.settings.settings.OAUTH_ENABLED", False):
        # Create a fresh app instance without OAuth routes
        app = Starlette()
        yield app


class TestOAuthEndpointsIntegration:
    """Integration tests for OAuth endpoints."""

    def test_oauth_register_endpoint_enabled(
        self, oauth_enabled_app: Starlette
    ) -> None:
        """Test OAuth register endpoint when OAuth is enabled."""
        app = oauth_enabled_app
        client = TestClient(app)

        with patch("assisted_service_mcp.src.oauth.settings.OAUTH_ENABLED", True):
            response = client.get("/oauth/register")

        assert response.status_code == 200
        data = response.json()
        assert "authorization_endpoint" in data
        assert "token_endpoint" in data
        assert "client_id" in data

    def test_oauth_callback_endpoint_enabled(
        self, oauth_enabled_app: Starlette
    ) -> None:
        """Test OAuth callback endpoint when OAuth is enabled."""
        app = oauth_enabled_app
        client = TestClient(app)

        with patch("assisted_service_mcp.src.oauth.settings.OAUTH_ENABLED", True):
            # Test with error parameter
            response = client.get("/oauth/callback?error=access_denied")

        assert response.status_code == 400
        assert "OAuth Authentication Failed" in response.text

    def test_oauth_token_endpoint_enabled(self, oauth_enabled_app: Starlette) -> None:
        """Test OAuth token endpoint when OAuth is enabled."""
        app = oauth_enabled_app
        client = TestClient(app)

        with patch("assisted_service_mcp.src.oauth.settings.OAUTH_ENABLED", True):
            # Test with invalid grant type
            response = client.post(
                "/oauth/token",
                json={
                    "grant_type": "client_credentials",
                    "code": "test_code",
                    "state": "test_state",
                },
            )

        assert response.status_code == 400
        # The response might be plain text or JSON
        if response.headers.get("content-type", "").startswith("application/json"):
            data = response.json()
            assert "Unsupported grant type" in data["detail"]
        else:
            assert "Unsupported grant type" in response.text
