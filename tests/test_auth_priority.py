"""Tests for authentication priority order implementation."""

from unittest.mock import MagicMock, patch


from assisted_service_mcp.utils.auth import get_access_token


class TestAuthenticationPriority:
    """Test cases for authentication priority order."""

    mock_mcp: MagicMock
    mock_context: MagicMock
    mock_request: MagicMock
    mock_headers: MagicMock

    def setup_method(self) -> None:
        """Set up test fixtures."""
        self.mock_mcp = MagicMock()
        self.mock_context = MagicMock()
        self.mock_request = MagicMock()

        # Setup mock headers with proper get method
        self.mock_headers = MagicMock()
        self.mock_request.headers = self.mock_headers

        self.mock_context.request_context.request = self.mock_request
        self.mock_mcp.get_context.return_value = self.mock_context

    def test_priority_1_authorization_header_bearer_token(self) -> None:
        """Test priority 1: Access token in Authorization header."""
        # Setup Authorization header with Bearer token
        self.mock_headers.get.return_value = "Bearer test_access_token"

        with patch("assisted_service_mcp.src.settings.settings.OAUTH_ENABLED", False):
            token = get_access_token(self.mock_mcp)

            assert token == "test_access_token"

    @patch("assisted_service_mcp.src.settings.settings.OAUTH_ENABLED", True)
    def test_priority_1_overrides_oauth(self) -> None:
        """Test that Authorization header (priority 1) overrides OAuth (priority 2)."""
        # Setup Authorization header
        self.mock_headers.get.return_value = "Bearer priority_1_token"

        def mock_oauth_func(_mcp):
            # This should not be called
            return "oauth_token"

        token = get_access_token(self.mock_mcp, oauth_token_func=mock_oauth_func)

        # Should return Authorization header token, not OAuth token
        assert token == "priority_1_token"

    def test_priority_2_oauth_when_no_auth_header(self) -> None:
        """Test priority 2: OAuth flow when no Authorization header."""

        # Setup headers to return None for Authorization header
        def mock_header_get(key, default=None):
            if key == "Authorization":
                return None
            return default

        self.mock_headers.get.side_effect = mock_header_get

        def mock_oauth_func(_mcp):
            return "oauth_access_token"

        with patch("assisted_service_mcp.utils.auth.settings.OAUTH_ENABLED", True):
            token = get_access_token(self.mock_mcp, oauth_token_func=mock_oauth_func)

        assert token == "oauth_access_token"

    @patch("assisted_service_mcp.src.settings.settings.OAUTH_ENABLED", False)
    @patch("requests.post")
    def test_offline_token_fallback_when_oauth_disabled(
        self, mock_post: MagicMock
    ) -> None:
        """Test offline token fallback when OAuth is disabled."""
        # No Authorization header
        self.mock_headers.get.return_value = None

        # Mock offline token retrieval
        with patch("assisted_service_mcp.utils.auth.get_offline_token") as mock_offline:
            mock_offline.return_value = "test_offline_token"

            # Mock SSO token exchange
            mock_response = MagicMock()
            mock_response.json.return_value = {"access_token": "exchanged_access_token"}
            mock_response.raise_for_status.return_value = None
            mock_post.return_value = mock_response

            with patch(
                "assisted_service_mcp.src.settings.get_setting"
            ) as mock_get_setting:
                mock_get_setting.return_value = "https://sso.example.com/token"

                token = get_access_token(self.mock_mcp)

                assert token == "exchanged_access_token"
                mock_offline.assert_called_once_with(self.mock_mcp)
