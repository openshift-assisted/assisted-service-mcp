"""ASGI application setup for the Assisted Service MCP server.

This module initializes the FastMCP server and creates an ASGI app
for deployment with uvicorn or any ASGI server.
"""

from assisted_service_mcp.src.mcp import AssistedServiceMCPServer
from assisted_service_mcp.src.settings import settings
from assisted_service_mcp.src.logger import log, configure_logging

# Ensure logging is configured before any module-level log usage
configure_logging()

# Initialize the MCP server
server = AssistedServiceMCPServer()

# Create ASGI app with appropriate transport
_SUPPORTED_TRANSPORTS = {"streamable-http", "http"}
if settings.TRANSPORT and settings.TRANSPORT not in _SUPPORTED_TRANSPORTS:
    log.warning(
        "Unsupported TRANSPORT=%r (supported: %s). Falling back to StreamableHTTP.",
        settings.TRANSPORT,
        ", ".join(sorted(_SUPPORTED_TRANSPORTS)),
    )
stateless = settings.TRANSPORT == "streamable-http"
app = server.mcp.http_app(stateless_http=stateless)
log.info("Using %s transport", "stateless StreamableHTTP" if stateless else "StreamableHTTP")
