"""Main entry point for the Assisted Service MCP Server."""

import uvicorn
from assisted_service_mcp.src.api import app, server
from assisted_service_mcp.src.settings import settings
from assisted_service_mcp.src.metrics import metrics, initiate_metrics
from assisted_service_mcp.src.logger import log


def main() -> None:
    """Start the MCP server.

    Initializes the server, sets up metrics, and starts the server with
    the configured transport (stdio, sse, or streamable-http).
    """
    try:
        log.info("Starting Assisted Service MCP Server")
        log.info(
            "Configuration: TRANSPORT=%s, HOST=%s, PORT=%s",
            settings.TRANSPORT,
            settings.MCP_HOST,
            settings.MCP_PORT,
        )

        # Initialize metrics with list of all tools
        tool_names = server.list_tools_sync()
        initiate_metrics(tool_names)
        log.info("Initialized metrics for %s tools", len(tool_names))

        # Handle stdio transport differently - no HTTP server needed
        if settings.TRANSPORT == "stdio":
            log.info("Running in stdio mode")
            # Run the MCP server directly with stdio transport
            server.mcp.run()
        else:
            # Add metrics endpoint for HTTP transports
            app.add_route("/metrics", metrics)
            log.info("Metrics endpoint available at /metrics")

            # Start the HTTP server using uvicorn
            uvicorn.run(app, host=settings.MCP_HOST, port=settings.MCP_PORT)

    except KeyboardInterrupt:
        log.info("Received keyboard interrupt, shutting down")
    except Exception as e:
        log.error("Server failed to start: %s", e, exc_info=True)
        raise
    finally:
        log.info("Assisted Service MCP server shutting down")


if __name__ == "__main__":
    main()
