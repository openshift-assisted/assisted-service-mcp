"""FastAPI application setup for the Assisted Service MCP server.

This module initializes the FastAPI app and sets up the MCP server
with appropriate transport protocols.
"""

from assisted_service_mcp.src.mcp import AssistedServiceMCPServer
from assisted_service_mcp.src.settings import settings
from assisted_service_mcp.src.logger import log, configure_logging

# Ensure logging is configured before any module-level log usage
configure_logging()

# Initialize the MCP server
server = AssistedServiceMCPServer()

# Choose the appropriate transport protocol based on settings
if settings.TRANSPORT == "stdio":
    # For stdio transport, no HTTP app is needed
    # The server will run directly via asyncio
    app = None  # type: ignore
    log.info("Using stdio transport (for Claude Code and CLI clients)")
elif settings.TRANSPORT == "streamable-http":
    app = server.mcp.streamable_http_app()
    log.info("Using StreamableHTTP transport (stateless)")
else:
    app = server.mcp.sse_app()
    log.info("Using SSE transport (stateful)")
