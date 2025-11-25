"""Assisted Service MCP server implementation."""

import asyncio
import inspect
import time
from functools import wraps
from typing import Any, Awaitable, Callable, Optional

from mcp.server.fastmcp import FastMCP
from assisted_service_mcp.src.logger import log

# Import auth utilities
from assisted_service_mcp.utils.auth import get_access_token
from assisted_service_mcp.src.settings import settings

# Import all tool modules
from assisted_service_mcp.src.tools import (
    cluster_tools,
    event_tools,
    download_tools,
    version_tools,
    operator_tools,
    host_tools,
    network_tools,
)


class AssistedServiceMCPServer:
    """Main Assisted Service MCP Server implementation.

    This server provides tools for managing OpenShift clusters through the
    Red Hat Assisted Installer API.
    """

    def __init__(self) -> None:
        """Initialize the MCP server with assisted service tools."""
        try:
            # Get transport configuration from settings
            use_stateless_http = settings.TRANSPORT == "streamable-http"

            # Initialize FastMCP server
            self.mcp = FastMCP(
                "AssistedService",
                host=settings.MCP_HOST,
                stateless_http=use_stateless_http,
            )
            self._get_oauth_token = self._create_oauth_token()
            self._get_access_token = lambda: get_access_token(
                self.mcp,
                oauth_token_func=self._get_oauth_token,
            )
            self._register_mcp_tools()
            log.info("Assisted Service MCP Server initialized successfully")
        except Exception as e:
            log.exception("Failed to initialize Assisted Service MCP Server: %s", e)
            raise

    def _create_oauth_token(self) -> Callable[[Any], Optional[str]]:
        """Create OAuth token function with proper dependency injection.

        This avoids circular imports by importing oauth module only when needed
        and creating a closure that captures the import.

        Returns:
            Function that can extract OAuth tokens from MCP context
        """

        def get_oauth_token(mcp: Any) -> Optional[str]:
            if not settings.OAUTH_ENABLED:
                return None

            try:
                # Import only when OAuth is enabled and function is called
                from assisted_service_mcp.src.oauth import (
                    get_oauth_access_token_from_mcp,
                    mcp_oauth_middleware,
                    oauth_manager,
                    open_browser_for_oauth,
                )

                # First check if we have a cached token
                cached_token = get_oauth_access_token_from_mcp(mcp)
                if cached_token:
                    return cached_token

                # Get client identifier for OAuth flow
                client_id = self._get_mcp_client_identifier(mcp)

                # Check if we have a completed OAuth token for this client
                token = oauth_manager.token_store.get_access_token_by_client(client_id)
                if token:
                    log.info("Using cached OAuth token for MCP client %s", client_id)
                    return token

                # Check if OAuth flow is already in progress for this client
                for (
                    session_id,
                    session_info,
                ) in mcp_oauth_middleware.pending_auth_sessions.items():
                    if session_info.get("client_id") == client_id:
                        log.info(
                            "OAuth flow already in progress for MCP client %s",
                            client_id,
                        )
                        raise RuntimeError(
                            "OAuth authentication in progress. Please complete the authentication in your browser, "
                            "then retry this command. The browser should have opened automatically."
                        )

                # Start new OAuth flow with PKCE
                log.info("Starting OAuth flow for MCP client %s", client_id)

                # Import OAuthState for parsing
                from assisted_service_mcp.src.oauth.models import OAuthState

                # Generate OAuth URL with PKCE parameters
                auth_url, state_json = oauth_manager.create_authorization_url(client_id)

                # Parse state to extract session_id
                state = OAuthState.from_json(state_json)
                session_id = state.session_id

                # Store session with full state_json for PKCE verification
                mcp_oauth_middleware.pending_auth_sessions[session_id] = {
                    "client_id": client_id,
                    "state": state_json,  # Store full JSON state with PKCE params
                    "auth_url": auth_url,
                    "timestamp": time.time(),
                }

                # Open browser automatically
                open_browser_for_oauth(auth_url)

                # Provide helpful error message for OAuth requirement
                raise RuntimeError(
                    "OAuth authentication required. Please complete the authentication in your browser "
                    "(it should have opened automatically), then retry this command."
                )

            except ImportError as e:
                log.warning("Failed to import OAuth module: %s", e)
                return None

        return get_oauth_token

    def _get_mcp_client_identifier(self, mcp: Any) -> str:
        """Get a unique identifier for the MCP client."""
        try:
            # Try to get client info from MCP context
            context = mcp.get_context()
            if (
                context
                and hasattr(context, "request_context")
                and context.request_context
            ):
                request = context.request_context.request
                if request:
                    user_agent = request.headers.get("user-agent", "unknown")
                    client_ip = (
                        getattr(request.client, "host", "unknown")
                        if request.client
                        else "unknown"
                    )
                    return f"{user_agent}_{client_ip}"

            # Fallback identifier
            return "mcp_client_unknown"
        except Exception:
            return "mcp_client_fallback"

    def _register_mcp_tools(self) -> None:
        """Register MCP tools for assisted service operations.

        Registers all available tools with the FastMCP server instance.
        Tools are organized by functional area:
        - Cluster management tools
        - Event monitoring tools
        - Download/URL tools
        - Version and operator tools
        - Host management tools
        - Network configuration tools
        """
        # Register cluster management tools
        self.mcp.tool()(self._wrap_tool(cluster_tools.cluster_info))
        self.mcp.tool()(self._wrap_tool(cluster_tools.list_clusters))
        self.mcp.tool()(self._wrap_tool(cluster_tools.create_cluster))
        self.mcp.tool()(self._wrap_tool(cluster_tools.set_cluster_vips))
        self.mcp.tool()(self._wrap_tool(cluster_tools.set_cluster_platform))
        self.mcp.tool()(self._wrap_tool(cluster_tools.install_cluster))
        self.mcp.tool()(self._wrap_tool(cluster_tools.set_cluster_ssh_key))
        if settings.ENABLE_TROUBLESHOOTING_TOOLS:
            self.mcp.tool()(self._wrap_tool(cluster_tools.analyze_cluster_logs))

        # Register event monitoring tools
        self.mcp.tool()(self._wrap_tool(event_tools.cluster_events))
        self.mcp.tool()(self._wrap_tool(event_tools.host_events))

        # Register download/URL tools
        self.mcp.tool()(self._wrap_tool(download_tools.cluster_iso_download_url))
        self.mcp.tool()(
            self._wrap_tool(download_tools.cluster_credentials_download_url)
        )

        # Register version tools
        self.mcp.tool()(self._wrap_tool(version_tools.list_versions))

        # Register operator bundle tools
        self.mcp.tool()(self._wrap_tool(operator_tools.list_operator_bundles))
        self.mcp.tool()(self._wrap_tool(operator_tools.add_operator_bundle_to_cluster))

        # Register host management tools
        self.mcp.tool()(self._wrap_tool(host_tools.set_host_role))

        # Register network configuration tools
        self.mcp.tool()(self._wrap_tool(network_tools.validate_nmstate_yaml))
        self.mcp.tool(
            description=f"""
            Generate an initial nmstate yaml.

            You should call this after gathering information from the user to generate the initial nmstate
            yaml. Then you can tweak it as needed. Do not generate nmstate yaml from scratch without calling
            this tool.

            Returns: the generated nmstate yaml

            Input param schema:
            {network_tools.NMStateTemplateParams.model_json_schema()}
        """
        )(self._wrap_tool(network_tools.generate_nmstate_yaml))
        self.mcp.tool()(
            self._wrap_tool(network_tools.alter_static_network_config_nmstate_for_host)
        )
        self.mcp.tool()(self._wrap_tool(network_tools.list_static_network_config))

    def _wrap_tool(
        self, tool_func: Callable[..., Awaitable[Any]]
    ) -> Callable[..., Awaitable[Any]]:
        """Wrap a tool function to inject mcp and auth dependencies.

        Args:
            tool_func: The tool function to wrap.

        Returns:
            A wrapped async function that injects mcp and get_access_token.
        """

        @wraps(tool_func)
        async def wrapped(*args: Any, **kwargs: Any) -> Any:
            # Generate token off the event loop; pass a cheap closure to tools
            token = await asyncio.to_thread(self._get_access_token)
            return await tool_func(lambda: token, *args, **kwargs)

        # Get the original function signature
        sig = inspect.signature(tool_func)
        params = list(sig.parameters.values())

        # Remove the first parameter (auth token provider) since it's injected by the wrapper
        if len(params) >= 1:
            params = params[1:]

        # Create new signature with remaining parameters
        new_sig = sig.replace(parameters=params)
        wrapped.__signature__ = new_sig  # type: ignore[attr-defined]

        return wrapped

    async def list_tools(self) -> list[str]:
        """List all registered MCP tools (async)."""
        return [t.name for t in await self.mcp.list_tools()]

    def list_tools_sync(self) -> list[str]:
        """Synchronize tool listing with a safe sync wrapper."""
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            # No running loop -> safe to use asyncio.run
            return asyncio.run(self.list_tools())

        # A loop is already running in this thread – do not nest.
        raise RuntimeError(
            "list_tools_sync() cannot be called from within a running event loop. "
            "Use 'await list_tools()' in async contexts."
        )
