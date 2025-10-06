"""Assisted Service MCP Server implementation.

This module contains the main Assisted Service MCP Server class that provides
tools for MCP clients. It uses FastMCP to register and manage MCP capabilities.
"""

import os
import asyncio
import inspect
from functools import wraps
from mcp.server.fastmcp import FastMCP
from service_client.logger import log

# Import auth utilities
from assisted_service_mcp.utils.auth import get_offline_token, get_access_token

# Import all tool modules
from assisted_service_mcp.src.tools import (
    cluster_tools,
    event_tools,
    download_tools,
    version_tools,
    host_tools,
    network_tools,
)


class AssistedServiceMCPServer:
    """Main Assisted Service MCP Server implementation.

    This server provides tools for managing OpenShift clusters through the
    Red Hat Assisted Installer API.
    """

    def __init__(self):
        """Initialize the MCP server with assisted service tools."""
        try:
            # Get transport configuration
            transport_type = os.environ.get("TRANSPORT", "sse").lower()
            use_stateless_http = transport_type == "streamable-http"

            # Initialize FastMCP server
            self.mcp = FastMCP(
                "AssistedService", host="0.0.0.0", stateless_http=use_stateless_http
            )

            # Create closures for auth functions that capture self.mcp
            self._get_offline_token = lambda: get_offline_token(self.mcp)
            self._get_access_token = lambda: get_access_token(self.mcp)

            self._register_mcp_tools()

            log.info("Assisted Service MCP Server initialized successfully")

        except Exception as e:
            log.error(f"Failed to initialize Assisted Service MCP Server: {e}")
            raise

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

        # Register event monitoring tools
        self.mcp.tool()(self._wrap_tool(event_tools.cluster_events))
        self.mcp.tool()(self._wrap_tool(event_tools.host_events))

        # Register download/URL tools
        self.mcp.tool()(self._wrap_tool(download_tools.cluster_iso_download_url))
        self.mcp.tool()(
            self._wrap_tool(download_tools.cluster_credentials_download_url)
        )

        # Register version and operator tools
        self.mcp.tool()(self._wrap_tool(version_tools.list_versions))
        self.mcp.tool()(self._wrap_tool(version_tools.list_operator_bundles))
        self.mcp.tool()(self._wrap_tool(version_tools.add_operator_bundle_to_cluster))

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

    def _wrap_tool(self, tool_func):
        """Wrap a tool function to inject mcp and auth dependencies.

        Args:
            tool_func: The tool function to wrap.

        Returns:
            A wrapped async function that injects mcp and get_access_token.
        """

        @wraps(tool_func)
        async def wrapped(*args, **kwargs):
            # Inject mcp instance and auth function as first two parameters
            return await tool_func(self.mcp, self._get_access_token, *args, **kwargs)

        # Get the original function signature
        sig = inspect.signature(tool_func)
        params = list(sig.parameters.values())

        # Remove the first two parameters (mcp and get_access_token_func)
        # since they're injected by the wrapper
        if len(params) >= 2 and params[0].name == "mcp" and params[1].name == "get_access_token_func":
            params = params[2:]

        # Create new signature with remaining parameters
        new_sig = sig.replace(parameters=params)
        wrapped.__signature__ = new_sig

        return wrapped

    def list_tools(self) -> list[str]:
        """List all registered MCP tools.

        Returns:
            list[str]: List of tool names.
        """

        async def mcp_list_tools() -> list[str]:
            return [t.name for t in await self.mcp.list_tools()]

        return asyncio.run(mcp_list_tools())

