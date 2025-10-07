"""Settings for the Assisted Service MCP Server."""

from typing import Optional

from dotenv import load_dotenv
from pydantic import Field, ConfigDict
from pydantic_settings import BaseSettings

# Load environment variables with error handling
try:
    load_dotenv()
except Exception:
    # Silently ignore - environment variables might be set directly
    pass


class Settings(BaseSettings):
    """Configuration settings for the Assisted Service MCP Server.

    Uses Pydantic BaseSettings to load and validate configuration from environment variables.
    Provides default values for optional settings and validation for required ones.
    """

    # MCP Server Configuration
    MCP_HOST: str = Field(
        default="0.0.0.0",
        json_schema_extra={
            "env": "MCP_HOST",
            "description": "Host address for the MCP server",
            "example": "localhost",
        },
    )
    MCP_PORT: int = Field(
        default=8000,
        ge=1024,
        le=65535,
        json_schema_extra={
            "env": "MCP_PORT",
            "description": "Port number for the MCP server",
            "example": 8000,
        },
    )
    
    # Transport Configuration
    TRANSPORT: str = Field(
        default="sse",
        json_schema_extra={
            "env": "TRANSPORT",
            "description": "Transport protocol for the MCP server",
            "example": "sse",
            "enum": ["sse", "streamable-http"],
        },
    )

    # Assisted Service API Configuration
    INVENTORY_URL: str = Field(
        default="https://api.openshift.com/api/assisted-install/v2",
        json_schema_extra={
            "env": "INVENTORY_URL",
            "description": "Assisted Service API base URL",
            "example": "https://api.openshift.com/api/assisted-install/v2",
        },
    )
    
    PULL_SECRET_URL: str = Field(
        default="https://api.openshift.com/api/accounts_mgmt/v1/access_token",
        json_schema_extra={
            "env": "PULL_SECRET_URL",
            "description": "URL for fetching pull secret",
            "example": "https://api.openshift.com/api/accounts_mgmt/v1/access_token",
        },
    )
    
    CLIENT_DEBUG: bool = Field(
        default=False,
        json_schema_extra={
            "env": "CLIENT_DEBUG",
            "description": "Enable debug mode for API client",
            "example": False,
        },
    )

    # Authentication Configuration
    OFFLINE_TOKEN: Optional[str] = Field(
        default=None,
        json_schema_extra={
            "env": "OFFLINE_TOKEN",
            "description": "OCM offline token for authentication",
            "example": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
            "sensitive": True,
        },
    )
    
    SSO_URL: str = Field(
        default="https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/token",
        json_schema_extra={
            "env": "SSO_URL",
            "description": "SSO token endpoint URL",
            "example": "https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/token",
        },
    )

    # Logging Configuration
    LOGGING_LEVEL: str = Field(
        default="INFO",
        json_schema_extra={
            "env": "LOGGING_LEVEL",
            "description": "Logging level for the application",
            "example": "INFO",
            "enum": ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        },
    )
    
    LOGGER_NAME: str = Field(
        default="",
        json_schema_extra={
            "env": "LOGGER_NAME",
            "description": "Name for the logger",
            "example": "assisted-service-mcp",
        },
    )
    
    LOG_TO_FILE: bool = Field(
        default=True,
        json_schema_extra={
            "env": "LOG_TO_FILE",
            "description": "Enable logging to file (disable in containers)",
            "example": True,
        },
    )

    model_config = ConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
    )


def validate_config(settings: Settings) -> None:
    """Validate configuration settings.

    Performs validation to ensure required settings are present and values
    are within acceptable ranges.

    Args:
        settings: Settings instance to validate.

    Raises:
        ValueError: If required configuration is missing or invalid.
    """
    # Validate port range
    if not (1024 <= settings.MCP_PORT <= 65535):
        raise ValueError(
            f"MCP_PORT must be between 1024 and 65535, got {settings.MCP_PORT}"
        )

    # Validate log level
    valid_log_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
    if settings.LOGGING_LEVEL.upper() not in valid_log_levels:
        raise ValueError(
            f"LOGGING_LEVEL must be one of {valid_log_levels}, got {settings.LOGGING_LEVEL}"
        )

    # Validate transport protocol
    valid_transports = ["sse", "streamable-http"]
    if settings.TRANSPORT not in valid_transports:
        raise ValueError(
            f"TRANSPORT must be one of {valid_transports}, got {settings.TRANSPORT}"
        )


# Create config instance without validation (validation happens in main.py if needed)
settings = Settings()

