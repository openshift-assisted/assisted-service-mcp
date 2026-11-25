"""Shared fake-archive helpers for log analyzer unit tests."""

from collections.abc import Mapping
from typing import Any


def make_archive(get_map: Mapping[str, object]) -> Any:
    """Create a fake archive with a .get(path) API from a mapping."""

    class _Archive:
        def get(self, path: str, **_kwargs: Any) -> object:
            if path in get_map:
                return get_map[path]
            raise FileNotFoundError(path)

    return _Archive()
