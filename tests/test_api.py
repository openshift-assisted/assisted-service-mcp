"""Unit tests for the MCP ASGI app transport, routes, and metrics endpoint."""

import importlib
import sys
from typing import Any

import pytest
from fastapi.testclient import TestClient


def load_app_with_transport(transport: str) -> Any:
    # Reload settings with desired transport
    settings_mod = importlib.import_module("assisted_service_mcp.src.settings")
    with pytest.MonkeyPatch().context() as mp:
        mp.setenv("TRANSPORT", transport)
        importlib.reload(settings_mod)
        # Reload api module to pick up new settings
        if "assisted_service_mcp.src.api" in sys.modules:
            del sys.modules["assisted_service_mcp.src.api"]
        api_mod = importlib.import_module("assisted_service_mcp.src.api")
        return api_mod


def test_api_uses_sse_when_configured() -> None:
    api_mod = load_app_with_transport("sse")
    assert api_mod.app.state.transport_type == "sse"
    assert api_mod.app.state.path == "/sse"


def test_api_uses_streamable_http_when_configured() -> None:
    api_mod = load_app_with_transport("streamable-http")
    assert api_mod.app.state.transport_type == "streamable-http"
    assert api_mod.app.state.path == "/mcp"


def ensure_metrics_route(app) -> None:  # type: ignore[no-untyped-def]
    # Attach /metrics route for the test (normally added in main())
    from assisted_service_mcp.src.metrics import (
        metrics as metrics_endpoint,
    )  # pylint: disable=import-outside-toplevel

    existing_paths = {r.path for r in getattr(app, "routes", []) if hasattr(r, "path")}
    if "/metrics" not in existing_paths:
        app.add_route("/metrics", metrics_endpoint)


@pytest.mark.parametrize("transport", ["sse", "streamable-http"])
def test_metrics_endpoint_present_and_exposes_prometheus(transport: str) -> None:
    api_mod = load_app_with_transport(transport)
    app = api_mod.app
    ensure_metrics_route(app)

    with TestClient(app) as client:
        resp = client.get("/metrics")
        assert resp.status_code == 200
        # Prometheus exposition format typically includes HELP/TYPE lines
        assert "HELP" in resp.text or "# HELP" in resp.text


@pytest.mark.parametrize(
    ("transport", "expected_paths"),
    [
        ("sse", {"/sse", "/messages"}),
        ("streamable-http", {"/mcp"}),
    ],
)
def test_transport_routes_are_mounted(transport: str, expected_paths: set[str]) -> None:
    """The app mounts MCP transport routes; there is no dedicated / liveness route."""
    api_mod = load_app_with_transport(transport)
    mounted_paths = {
        route.path for route in api_mod.app.routes if hasattr(route, "path")
    }
    assert expected_paths.issubset(mounted_paths)


def test_supported_transports_match_settings() -> None:
    api_mod = load_app_with_transport("sse")
    assert api_mod.SUPPORTED_TRANSPORTS == {"sse", "streamable-http"}
