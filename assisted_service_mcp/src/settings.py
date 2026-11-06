"""Settings for the MCP server for Red Hat OpenShift assisted installer."""

from typing import Optional, ClassVar
from typing import Literal
from typing import Any

from dotenv import load_dotenv
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Load environment variables with error handling
try:
    load_dotenv()
except FileNotFoundError:
    # Expected when .env doesn't exist
    pass
except Exception as e:
    # Log unexpected errors but don't fail
    import warnings

    warnings.warn(f"Failed to load .env file: {e}")


class Settings(BaseSettings):
    """Configuration settings for the MCP server for Red Hat OpenShift assisted installer.

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
    TRANSPORT: Literal["sse", "streamable-http"] = Field(
        default="streamable-http",
        json_schema_extra={
            "env": "TRANSPORT",
            "description": "Transport protocol for the MCP server",
            "example": "streamable-http",
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
    LOGGING_LEVEL: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = Field(
        default="INFO",
        json_schema_extra={
            "env": "LOGGING_LEVEL",
            "description": "Logging level for the application",
            "example": "INFO",
        },
    )

    # Accept lower/any-case input from env (e.g., "debug") and normalize
    @field_validator("LOGGING_LEVEL", mode="before")
    @classmethod
    def _normalize_logging_level(cls, v):  # type: ignore[no-untyped-def]
        return v.upper() if isinstance(v, str) else v

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

    ENABLE_TROUBLESHOOTING_TOOLS: int = Field(
        default=0,
        ge=0,
        le=1,
        json_schema_extra={
            "env": "ENABLE_TROUBLESHOOTING_TOOLS",
            "description": "Whether the troubleshooting tool call(s) should be enabled",
            "example": 0,
        },
    )

    model_config: ClassVar[SettingsConfigDict] = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": True,
        # Enable runtime assignment so tests can patch settings fields
        "validate_assignment": True,
        "frozen": False,
    }


# Create and validate the configuration from environment variables.
settings = Settings()


def get_setting(name: str) -> Any:
    """Return setting value, honoring runtime test patches.

    unittest.mock.patch may set attributes directly on the instance which can
    bypass pydantic's internal field store. Prefer a direct __dict__ lookup
    first, then fall back to normal attribute access.
    """
    if name in settings.__dict__:
        return settings.__dict__[name]
    return getattr(settings, name)
