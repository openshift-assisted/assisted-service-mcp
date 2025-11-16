"""Centralized OAuth token storage.

This replaces the multiple token storage mechanisms that were spread across
oauth.py and mcp_oauth_middleware.py.
"""

import time
from typing import Dict, Optional

from assisted_service_mcp.src.logger import log
from assisted_service_mcp.src.oauth.models import OAuthToken


class TokenStore:
    """Centralized token storage with clear interface.

    This consolidates:
    - oauth_manager._tokens (token_id -> token data)
    - mcp_oauth_middleware.completed_tokens (client_id -> token_id)

    Into a single, well-defined storage mechanism.
    """

    def __init__(self) -> None:
        """Initialize token store."""
        self._tokens: Dict[str, OAuthToken] = {}
        self._client_tokens: Dict[str, str] = {}  # client_id -> token_id

    def store_token(self, token: OAuthToken) -> None:
        """Store a token and associate it with a client.

        Args:
            token: OAuthToken to store
        """
        self._tokens[token.token_id] = token
        self._client_tokens[token.client_id] = token.token_id
        log.debug(
            "Stored token %s for client %s (expires at %s)",
            token.token_id,
            token.client_id,
            token.expires_at,
        )

    def get_token_by_id(self, token_id: str) -> Optional[OAuthToken]:
        """Get token by token ID.

        Args:
            token_id: Token identifier

        Returns:
            OAuthToken if found and valid, None otherwise
        """
        token = self._tokens.get(token_id)
        if not token:
            return None

        if token.is_expired():
            log.debug("Token %s is expired, removing from store", token_id)
            self.remove_token(token_id)
            return None

        return token

    def get_token_by_client(self, client_id: str) -> Optional[OAuthToken]:
        """Get token for a client.

        Args:
            client_id: Client identifier

        Returns:
            OAuthToken if found and valid, None otherwise
        """
        token_id = self._client_tokens.get(client_id)
        if not token_id:
            return None

        return self.get_token_by_id(token_id)

    def get_access_token_by_id(self, token_id: str) -> Optional[str]:
        """Get access token string by token ID.

        Args:
            token_id: Token identifier

        Returns:
            Access token string if found and valid, None otherwise
        """
        token = self.get_token_by_id(token_id)
        return token.access_token if token else None

    def get_access_token_by_client(self, client_id: str) -> Optional[str]:
        """Get access token string for a client.

        Args:
            client_id: Client identifier

        Returns:
            Access token string if found and valid, None otherwise
        """
        token = self.get_token_by_client(client_id)
        return token.access_token if token else None

    def update_token(
        self,
        token_id: str,
        access_token: str,
        refresh_token: Optional[str],
        expires_at: float,
    ) -> bool:
        """Update an existing token (e.g., after refresh).

        Args:
            token_id: Token identifier
            access_token: New access token
            refresh_token: New refresh token (optional)
            expires_at: New expiration timestamp

        Returns:
            True if token was updated, False if token not found
        """
        token = self._tokens.get(token_id)
        if not token:
            return False

        token.access_token = access_token
        if refresh_token:
            token.refresh_token = refresh_token
        token.expires_at = expires_at

        log.debug("Updated token %s (new expiry: %s)", token_id, expires_at)
        return True

    def remove_token(self, token_id: str) -> None:
        """Remove a token and its associations.

        Args:
            token_id: Token identifier to remove
        """
        token = self._tokens.pop(token_id, None)
        if token:
            self._client_tokens.pop(token.client_id, None)
            log.debug("Removed token %s for client %s", token_id, token.client_id)

    def remove_client_token(self, client_id: str) -> None:
        """Remove token associated with a client.

        Args:
            client_id: Client identifier
        """
        token_id = self._client_tokens.get(client_id)
        if token_id:
            self.remove_token(token_id)

    def cleanup_expired_tokens(self) -> int:
        """Clean up expired tokens.

        Returns:
            Number of tokens removed
        """
        current_time = time.time()
        expired_token_ids = [
            token_id
            for token_id, token in self._tokens.items()
            if current_time >= token.expires_at
        ]

        for token_id in expired_token_ids:
            self.remove_token(token_id)

        if expired_token_ids:
            log.info("Cleaned up %d expired tokens", len(expired_token_ids))

        return len(expired_token_ids)

    def get_all_tokens(self) -> Dict[str, OAuthToken]:
        """Get all stored tokens (for debugging/monitoring).

        Returns:
            Dictionary of token_id -> OAuthToken
        """
        return self._tokens.copy()

    def get_token_count(self) -> int:
        """Get number of stored tokens.

        Returns:
            Number of tokens in store
        """
        return len(self._tokens)
