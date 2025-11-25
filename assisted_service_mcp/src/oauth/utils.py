"""Shared OAuth utilities to reduce code duplication."""

import webbrowser
from typing import Any, Dict

from fastapi import Request

from assisted_service_mcp.src.logger import log


def open_browser_for_oauth(auth_url: str) -> None:
    """Open browser for OAuth authentication with error handling.

    Args:
        auth_url: The OAuth authorization URL to open
    """
    try:
        webbrowser.open(auth_url)
        log.info("Opened browser for OAuth authentication: %s", auth_url)
    except Exception as e:
        log.warning("Could not open browser automatically: %s", e)


def get_oauth_success_html(is_mcp_flow: bool = False, session_id: str = "") -> str:
    """Generate OAuth success HTML page.

    Args:
        is_mcp_flow: Whether this is an MCP automatic flow
        session_id: Session ID for display (optional)

    Returns:
        HTML content for success page
    """
    instructions_html = ""
    if is_mcp_flow:
        instructions_html = """
        <div class="instructions">
            <h3>For MCP Clients (Cursor/Copilot):</h3>
            <ol>
                <li>Close this browser window</li>
                <li>Return to Cursor</li>
                <li>Try your MCP command again (e.g., "list my clusters")</li>
                <li>The connection should now work with your authenticated token</li>
            </ol>
        </div>
        """
    else:
        instructions_html = """
        <div class="instructions">
            <h3>Next Steps:</h3>
            <ol>
                <li>Close this browser window</li>
                <li>Return to Cursor/Copilot</li>
                <li>Your MCP connection should now work automatically</li>
            </ol>
        </div>
        """

    session_display = (
        f"<p><small>Session ID: {session_id}</small></p>" if session_id else ""
    )
    auto_close_delay = "3000" if is_mcp_flow else "5000"
    return f"""
    <html>
        <head>
            <title>Authentication Successful</title>
            <style>
                body {{ font-family: Arial, sans-serif; text-align: center; padding: 50px; }}
                .success {{ color: #28a745; }}
                .instructions {{ background: #f8f9fa; padding: 20px; border-radius: 5px; margin: 20px 0; }}
            </style>
        </head>
        <body>
            <h1 class="success">🎉 Authentication Successful!</h1>
            <p>You have successfully authenticated with the Assisted Service MCP server.</p>
            {instructions_html}
            {session_display}
            <script>
                // Auto-close after a few seconds
                setTimeout(() => {{
                    window.close();
                }}, {auto_close_delay});
            </script>
        </body>
    </html>
    """


def extract_oauth_callback_params(request: Request) -> Dict[str, Any]:
    """Extract and validate OAuth callback parameters.

    Args:
        request: FastAPI request object

    Returns:
        Dictionary with code, state, and error parameters
    """
    return {
        "code": request.query_params.get("code"),
        "state": request.query_params.get("state"),
        "error": request.query_params.get("error"),
    }
