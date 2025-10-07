"""FastAPI application setup for the Assisted Service MCP server.

This module initializes the FastAPI app and sets up the MCP server
with appropriate transport protocols.
"""

from assisted_service_mcp.src.mcp import AssistedServiceMCPServer
from assisted_service_mcp.src.settings import settings
from service_client.logger import log

# Initialize the MCP server
server = AssistedServiceMCPServer()

# Choose the appropriate transport protocol based on settings
if settings.TRANSPORT.lower() == "streamable-http":
    app = server.mcp.streamable_http_app()
    log.info("Using StreamableHTTP transport (stateless)")
else:
    app = server.mcp.sse_app()
    log.info("Using SSE transport (stateful)")

