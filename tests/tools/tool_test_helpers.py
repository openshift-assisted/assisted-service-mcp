"""Shared setup helpers for MCP tool unit tests that mock InventoryClient."""

from collections.abc import Awaitable, Iterator
from contextlib import contextmanager
from typing import TypeVar
from unittest.mock import AsyncMock, Mock, patch

TEST_TOKEN = "test-access-token"

T = TypeVar("T")


def test_token() -> str:
    """Zero-arg token callable passed into tool functions under test."""
    return TEST_TOKEN


@contextmanager
def patch_inventory_client(import_path: str, client: Mock) -> Iterator[Mock]:
    """Patch InventoryClient where a tool module imports it."""
    with patch(import_path, return_value=client) as inventory_client:
        yield inventory_client


async def invoke_with_client(
    import_path: str,
    client: Mock,
    tool_call: Awaitable[T],
) -> tuple[T, Mock]:
    """Await a tool call while InventoryClient is patched to return client."""
    with patch_inventory_client(import_path, client) as inventory_client:
        result = await tool_call
    return result, inventory_client


def mock_to_str_result(text: str) -> Mock:
    """Build an API result object that exposes to_str()."""
    result = Mock()
    result.to_str.return_value = text
    return result


def update_cluster_client(text: str = "UPDATED") -> Mock:
    """InventoryClient mock whose update_cluster returns a to_str result."""
    client = Mock()
    client.update_cluster = AsyncMock(return_value=mock_to_str_result(text))
    return client


def events_client(events: str) -> Mock:
    """InventoryClient mock whose get_events returns the given events payload."""
    client = Mock()
    client.get_events = AsyncMock(return_value=events)
    return client
