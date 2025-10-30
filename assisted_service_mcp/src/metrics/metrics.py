"""
Metrics for the MCP server.

This module provides metrics for the MCP server.
"""

from typing import Callable, Any
from functools import wraps

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    Counter,
    Histogram,
    generate_latest,
)
from starlette.requests import Request
from starlette.responses import PlainTextResponse


# Define counter for request count
REQUEST_COUNT = Counter(
    "assisted_service_mcp_tool_request_count",
    "Request count",
    ["tool"],
)

# Define histogram for request latency
REQUEST_LATENCY = Histogram(
    "assisted_service_mcp_tool_request_duration",
    "Request latency",
    ["tool"],
    buckets=(0.05, 0.1, 0.5, 1.0, 5.0, 10.0, float("inf")),
)

# Define histogram for API call latency
API_CALL_LATENCY = Histogram(
    "assisted_service_api_call_duration_seconds",
    "Duration of API calls to Assisted Service",
    ["api_method"],
    buckets=(0.05, 0.1, 0.5, 1.0, 5.0, 10.0, float("inf")),
)


def initiate_metrics(tools: list[str]) -> None:
    """Initiate metrics."""
    for tool in tools:
        REQUEST_COUNT.labels(tool=tool).inc()
        REQUEST_LATENCY.labels(tool=tool).observe(0)


def track_tool_usage() -> Callable:
    """Decorate MCP tools with this decorator to track tool usage metrics."""

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            tool_name = func.__name__
            REQUEST_COUNT.labels(tool=tool_name).inc()
            with REQUEST_LATENCY.labels(tool=tool_name).time():
                response = await func(*args, **kwargs)
            return response

        return wrapper

    return decorator


# Metrics route
async def metrics(_request: Request) -> PlainTextResponse:
    """Metrics endpoint."""
    return PlainTextResponse(generate_latest(), media_type=CONTENT_TYPE_LATEST)
