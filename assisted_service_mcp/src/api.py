"""FastAPI application setup for the Assisted Service MCP server.

This module initializes the FastAPI app and sets up the MCP server
with appropriate transport protocols.
"""

import os
from assisted_service_mcp.src.mcp import AssistedServiceMCPServer
from service_client.logger import log

# Initialize the MCP server
server = AssistedServiceMCPServer()

# Get transport configuration
transport_type = os.environ.get("TRANSPORT", "sse").lower()

# Choose the appropriate transport protocol
if transport_type == "streamable-http":
    app = server.mcp.streamable_http_app()
    log.info("Using StreamableHTTP transport (stateless)")
else:
    app = server.mcp.sse_app()
    log.info("Using SSE transport (stateful)")

