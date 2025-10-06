"""Main entry point for the Assisted Service MCP Server."""

import uvicorn
from assisted_service_mcp.src.api import app, server
from metrics import metrics, initiate_metrics
from service_client.logger import log


def main() -> None:
    """Main entry point for the MCP server.

    Initializes the server, sets up metrics, and starts the uvicorn server.
    """
    try:
        log.info("Starting Assisted Service MCP Server")

        # Initialize metrics with list of all tools
        tool_names = server.list_tools()
        initiate_metrics(tool_names)
        log.info(f"Initialized metrics for {len(tool_names)} tools")

        # Add metrics endpoint
        app.add_route("/metrics", metrics)
        log.info("Metrics endpoint available at /metrics")

        # Start the server
        uvicorn.run(app, host="0.0.0.0")

    except KeyboardInterrupt:
        log.info("Received keyboard interrupt, shutting down")
    except Exception as e:
        log.error(f"Server failed to start: {e}", exc_info=True)
        raise
    finally:
        log.info("Assisted Service MCP server shutting down")


if __name__ == "__main__":
    main()

