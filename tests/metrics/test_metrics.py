import asyncio

from prometheus_client import REGISTRY, generate_latest

from assisted_service_mcp.src.metrics import initiate_metrics, track_tool_usage


def _read_tool_request_metrics(
    tool_name: str,
) -> tuple[float | None, float | None]:
    """Return (request counter total, duration observation count) for the named tool; either may be None if absent."""
    counter_value = None
    histogram_count = None
    for metric in REGISTRY.collect():
        for sample in metric.samples:
            if (
                sample.name == "assisted_service_mcp_tool_request_count_total"
                and sample.labels.get("tool") == tool_name
            ):
                counter_value = sample.value
            if (
                sample.name == "assisted_service_mcp_tool_request_duration_count"
                and sample.labels.get("tool") == tool_name
            ):
                histogram_count = sample.value
    return counter_value, histogram_count


# Verify decorated calls preserve results and each record one request and duration observation.
def test_track_tool_usage_decorator_counts_and_times() -> None:
    tool_name = "test_track_tool_usage_decorator_counts_and_times_tool"
    initiate_metrics([tool_name])  # ensure labeled series exists

    async def _impl(x: int) -> int:
        await asyncio.sleep(0)
        return x + 1

    # Ensure the decorator labels with our tool_name
    _impl.__name__ = tool_name  # type: ignore[attr-defined]
    wrapped = track_tool_usage()(_impl)

    before_counter, before_hist = _read_tool_request_metrics(tool_name)
    assert before_counter == 0.0
    assert before_hist == 0.0

    # Two calls should increase counters by exactly 2 for this label
    assert asyncio.run(wrapped(1)) == 2
    assert asyncio.run(wrapped(2)) == 3

    after_counter, after_hist = _read_tool_request_metrics(tool_name)

    assert (
        after_counter is not None and (after_counter - (before_counter or 0.0)) == 2.0
    )
    assert after_hist is not None and (after_hist - (before_hist or 0.0)) == 2.0


def test_initiate_metrics_initializes_series_without_recording_requests() -> None:
    tool = "test_initiate_metrics_initializes_series_without_recording_requests_tool"
    # Initialization registers zero-valued series without recording requests.
    initiate_metrics([tool])
    assert _read_tool_request_metrics(tool) == (0.0, 0.0)
    initiate_metrics([tool])
    assert _read_tool_request_metrics(tool) == (0.0, 0.0)

    async def _impl(x: int) -> int:
        await asyncio.sleep(0)
        return x + 1

    _impl.__name__ = tool  # type: ignore[attr-defined]
    wrapped = track_tool_usage()(_impl)

    # Exercise decorator; then assert label appears in scrape output
    assert asyncio.run(wrapped(1)) == 2
    output = generate_latest().decode()
    assert f'tool="{tool}"' in output

    # Re-initializing after a real request must not change request metrics.
    initiate_metrics([tool])
    assert _read_tool_request_metrics(tool) == (1.0, 1.0)
    assert asyncio.run(wrapped(2)) == 3
    assert _read_tool_request_metrics(tool) == (2.0, 2.0)
    output2 = generate_latest().decode()
    assert f'tool="{tool}"' in output2
