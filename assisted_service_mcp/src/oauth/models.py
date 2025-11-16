"""OAuth data models for type safety and clarity."""

import json
import time
from dataclasses import dataclass
from typing import Any, Optional


@dataclass
class OAuthToken:
    """Unified OAuth token model.

    This consolidates token information that was previously spread across
    multiple dictionaries with different structures.

    Supports dictionary-style access for backward compatibility.
    """

    token_id: str
    client_id: str
    access_token: str
    refresh_token: Optional[str]
    expires_at: float
    token_type: str = "Bearer"

    def is_expired(self) -> bool:
        """Check if token is expired.

        Returns:
            True if token is expired, False otherwise
        """
        return time.time() >= self.expires_at

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "token_id": self.token_id,
            "client_id": self.client_id,
            "access_token": self.access_token,
            "token_type": self.token_type,
            "refresh_token": self.refresh_token,
            "expires_at": self.expires_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "OAuthToken":
        """Create from dictionary."""
        return cls(
            token_id=data["token_id"],
            client_id=data["client_id"],
            access_token=data["access_token"],
            refresh_token=data.get("refresh_token"),
            expires_at=data["expires_at"],
            token_type=data.get("token_type", "Bearer"),
        )

    def __getitem__(self, key: str) -> Any:
        """Support dictionary-style access for backward compatibility.

        Args:
            key: Attribute name

        Returns:
            Attribute value
        """
        if key == "token_id":
            return self.token_id
        if key == "access_token":
            return self.access_token
        if key == "token_type":
            return self.token_type
        if key == "refresh_token":
            return self.refresh_token
        if key == "expires_at":
            return self.expires_at
        if key == "client_id":
            return self.client_id
        raise KeyError(f"Unknown key: {key}")

    def __contains__(self, key: str) -> bool:
        """Support 'in' operator for backward compatibility."""
        return key in [
            "token_id",
            "access_token",
            "token_type",
            "refresh_token",
            "expires_at",
            "client_id",
        ]

    def get(self, key: str, default: Any = None) -> Any:
        """Support dict.get() for backward compatibility."""
        try:
            return self[key]
        except KeyError:
            return default


@dataclass
class OAuthState:
    """Structured OAuth state for CSRF protection.

    Replaces string concatenation with proper JSON serialization.
    """

    session_id: str
    client_id: str
    timestamp: float
    code_verifier: str

    def to_json(self) -> str:
        """Serialize to JSON string for use as OAuth state parameter.

        Returns:
            JSON string representation
        """
        return json.dumps(
            {
                "session_id": self.session_id,
                "client_id": self.client_id,
                "timestamp": self.timestamp,
                "code_verifier": self.code_verifier,
            }
        )

    @classmethod
    def from_json(cls, state_str: str) -> "OAuthState":
        """Deserialize from JSON string.

        Args:
            state_str: JSON string from OAuth state parameter

        Returns:
            OAuthState instance

        Raises:
            ValueError: If state string is invalid
        """
        try:
            data = json.loads(state_str)
            return cls(
                session_id=data["session_id"],
                client_id=data["client_id"],
                timestamp=data["timestamp"],
                code_verifier=data["code_verifier"],
            )
        except (json.JSONDecodeError, KeyError) as e:
            raise ValueError(f"Invalid OAuth state: {e}") from e

    def is_expired(self, max_age_seconds: int = 600) -> bool:
        """Check if state is too old.

        Args:
            max_age_seconds: Maximum age in seconds (default 10 minutes)

        Returns:
            True if state is expired, False otherwise
        """
        return time.time() - self.timestamp > max_age_seconds
