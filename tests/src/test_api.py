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

    existing_paths = {
        getattr(r, "path") for r in getattr(app, "routes", []) if hasattr(r, "path")
    }
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


@pytest.mark.parametrize("transport", ["sse", "streamable-http"])
def test_basic_liveness_returns_response(transport: str) -> None:
    api_mod = load_app_with_transport(transport)
    app = api_mod.app

    with TestClient(app) as client:
        resp = client.get("/")
        assert resp.status_code in (200, 404, 405)


def test_supported_transports_match_settings() -> None:
    api_mod = load_app_with_transport("sse")
    assert getattr(api_mod, "_SUPPORTED_TRANSPORTS") == {"sse", "streamable-http"}
