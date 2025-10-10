import asyncio
from fastapi import FastAPI
from fastapi.testclient import TestClient

from prometheus_client import REGISTRY, generate_latest
from assisted_service_mcp.src.metrics import initiate_metrics, metrics, track_tool_usage


def test_metrics_endpoint_returns_prometheus() -> None:
    app = FastAPI()
    app.add_route("/metrics", metrics)
    with TestClient(app) as client:
        resp = client.get("/metrics")
        assert resp.status_code == 200
        assert "# HELP" in resp.text or "HELP" in resp.text


def test_track_tool_usage_decorator_counts_and_times() -> None:
    tool_name = "test_track_tool_usage_decorator_counts_and_times_unique_tool"
    initiate_metrics([tool_name])  # ensure labeled series exists

    async def _impl(x: int) -> int:
        await asyncio.sleep(0)
        return x + 1

    # Ensure the decorator labels with our tool_name
    _impl.__name__ = tool_name  # type: ignore[attr-defined]
    wrapped = track_tool_usage()(_impl)

    def _read_values() -> tuple[float | None, float | None]:
        c_val = None
        h_val = None
        for metric in REGISTRY.collect():
            for sample in metric.samples:
                if (
                    sample.name == "assisted_service_mcp_tool_request_count_total"
                    and sample.labels.get("tool") == tool_name
                ):
                    c_val = sample.value
                if (
                    sample.name == "assisted_service_mcp_tool_request_duration_count"
                    and sample.labels.get("tool") == tool_name
                ):
                    h_val = sample.value
        return c_val, h_val

    before_counter, before_hist = _read_values()

    # Two calls should increase counters by exactly 2 for this label
    assert asyncio.run(wrapped(1)) == 2
    assert asyncio.run(wrapped(2)) == 3

    after_counter, after_hist = _read_values()

    assert (
        after_counter is not None and (after_counter - (before_counter or 0.0)) == 2.0
    )
    assert after_hist is not None and (after_hist - (before_hist or 0.0)) == 2.0


def test_initiate_metrics_idempotent() -> None:
    tool = "test_initiate_metrics_idempotent_tool"
    # First call should register label and create initial observation
    initiate_metrics([tool])
    _ = generate_latest()  # force scrape to register series

    async def _impl(x: int) -> int:
        await asyncio.sleep(0)
        return x + 1

    _impl.__name__ = tool  # type: ignore[attr-defined]
    wrapped = track_tool_usage()(_impl)

    # Exercise decorator; then assert label appears in scrape output
    assert asyncio.run(wrapped(1)) == 2
    output = generate_latest().decode()
    assert f'tool="{tool}"' in output

    # Calling initiate_metrics again should be harmless (idempotent in the sense of no error)
    # Note: current implementation also adds an observation (0), so count may increase by 1.
    initiate_metrics([tool])
    _ = generate_latest()
    assert asyncio.run(wrapped(2)) == 3
    output2 = generate_latest().decode()
    assert f'tool="{tool}"' in output2
