"""Assisted Service MCP server implementation."""

import asyncio
import inspect
from functools import wraps
from importlib import resources
from pathlib import Path
from typing import Any, Awaitable, Callable

from fastmcp import FastMCP
from fastmcp.apps import AppConfig, ResourceCSP
from assisted_service_mcp.src.logger import log

# Import auth utilities
from assisted_service_mcp.utils.auth import get_offline_token, get_access_token
from assisted_service_mcp.src.settings import settings

# Import all tool modules
from assisted_service_mcp.src.tools import (
    cluster_tools,
    event_tools,
    download_tools,
    version_tools,
    operator_tools,
    host_tools,
    health_tools,
    network_tools,
)

# --- MCP Apps: UI resource URIs ---
INVENTORY_RESOURCE_URI = "ui://cluster-inventory"
CREATOR_RESOURCE_URI = "ui://cluster-creator"
SETUP_RESOURCE_URI = "ui://cluster-setup"

_APP_CSP = AppConfig(csp=ResourceCSP(resource_domains=["https://unpkg.com"]))


def _load_html(package: str, filename: str) -> str:
    """Load an HTML dashboard file from package data."""
    try:
        return (
            resources.files(package)
            .joinpath(filename)
            .read_text(encoding="utf-8")
        )
    except (FileNotFoundError, ModuleNotFoundError, AttributeError, TypeError):
        return (Path(__file__).parent / "tools" / filename).read_text(
            encoding="utf-8"
        )


INVENTORY_HTML = _load_html(
    "assisted_service_mcp.src.tools", "cluster_inventory.html"
)
CREATOR_HTML = _load_html(
    "assisted_service_mcp.src.tools", "cluster_creator.html"
)
SETUP_HTML = _load_html(
    "assisted_service_mcp.src.tools", "cluster_setup.html"
)


class AssistedServiceMCPServer:
    """Main Assisted Service MCP Server implementation.

    This server provides tools for managing OpenShift clusters through the
    Red Hat Assisted Installer API.
    """

    def __init__(self) -> None:
        """Initialize the MCP server with assisted service tools."""
        try:
            # Initialize FastMCP server
            self.mcp = FastMCP("AssistedService")
            # Define auth helpers bound to this MCP instance
            self._get_offline_token = lambda: get_offline_token(self.mcp)
            self._get_access_token = lambda: get_access_token(
                self.mcp, offline_token_func=self._get_offline_token
            )
            self._register_ui_resources()
            self._register_mcp_tools()
            log.info("Assisted Service MCP Server initialized successfully")
        except Exception as e:
            log.exception("Failed to initialize Assisted Service MCP Server: %s", e)
            raise

    def _register_ui_resources(self) -> None:
        """Register MCP Apps UI dashboard resources."""

        @self.mcp.resource(INVENTORY_RESOURCE_URI, app=_APP_CSP)
        def cluster_inventory_ui() -> str:
            """Cluster Inventory dashboard for browsing OpenShift clusters."""
            return INVENTORY_HTML

        @self.mcp.resource(CREATOR_RESOURCE_URI, app=_APP_CSP)
        def cluster_creator_ui() -> str:
            """Cluster Creator dashboard for creating new OpenShift clusters."""
            return CREATOR_HTML

        @self.mcp.resource(SETUP_RESOURCE_URI, app=_APP_CSP)
        def cluster_setup_ui() -> str:
            """Cluster Setup dashboard for host registration and installation."""
            return SETUP_HTML

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
        _inv = AppConfig(resource_uri=INVENTORY_RESOURCE_URI)
        _cre = AppConfig(resource_uri=CREATOR_RESOURCE_URI)
        _set = AppConfig(resource_uri=SETUP_RESOURCE_URI)

        # Widget-opening tools (app= makes them render a UI dashboard)
        self.mcp.tool(app=_inv)(self._wrap_tool(cluster_tools.list_clusters))
        self.mcp.tool(app=_cre)(
            self._wrap_tool(cluster_tools.load_creator_dashboard)
        )
        self.mcp.tool(app=_set)(self._wrap_tool(host_tools.get_cluster_hosts))

        # Cluster management tools (called from within widgets or by LLM)
        self.mcp.tool()(self._wrap_tool(cluster_tools.cluster_info))
        self.mcp.tool()(self._wrap_tool(cluster_tools.create_cluster))
        self.mcp.tool()(self._wrap_tool(cluster_tools.set_cluster_vips))
        self.mcp.tool()(self._wrap_tool(cluster_tools.set_cluster_platform))
        self.mcp.tool()(self._wrap_tool(cluster_tools.install_cluster))
        self.mcp.tool()(self._wrap_tool(cluster_tools.set_cluster_ssh_key))
        if settings.ENABLE_TROUBLESHOOTING_TOOLS:
            self.mcp.tool()(self._wrap_tool(cluster_tools.analyze_cluster_logs))

        # Event monitoring tools
        self.mcp.tool()(self._wrap_tool(event_tools.cluster_events))
        self.mcp.tool()(self._wrap_tool(event_tools.host_events))

        # Download/URL tools
        self.mcp.tool()(
            self._wrap_tool(download_tools.cluster_iso_download_url)
        )
        self.mcp.tool()(
            self._wrap_tool(download_tools.cluster_credentials_download_url)
        )
        self.mcp.tool()(
            self._wrap_tool(download_tools.cluster_logs_download_url)
        )

        # Version tools
        self.mcp.tool()(self._wrap_tool(version_tools.list_versions))

        # Operator bundle tools
        self.mcp.tool()(self._wrap_tool(operator_tools.list_operator_bundles))
        self.mcp.tool()(self._wrap_tool(operator_tools.add_operator_bundle_to_cluster))

        # Host management tools
        self.mcp.tool()(self._wrap_tool(host_tools.set_host_role))

        # Installation progress
        self.mcp.tool()(
            self._wrap_tool(cluster_tools.get_installation_progress)
        )

        # Health check
        self.mcp.tool()(self._wrap_tool(health_tools.check_prerequisites))

        # Network configuration tools
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
            token = await asyncio.to_thread(self._get_access_token)
            result = await tool_func(lambda: token, *args, **kwargs)
            if isinstance(result, bytes):
                result = result.decode("utf-8", errors="replace")
            return result

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
