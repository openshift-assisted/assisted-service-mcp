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
stateless = settings.TRANSPORT == "streamable-http"
app = server.mcp.http_app(stateless_http=stateless)
log.info("Using %s transport", "stateless StreamableHTTP" if stateless else "StreamableHTTP")
