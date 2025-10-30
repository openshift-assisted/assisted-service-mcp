"""
Exception handling utilities for the Assisted Service client.

This module provides custom exception classes and decorators for sanitizing
exceptions from the Assisted Service API.
"""

from typing import Callable, TypeVar, ParamSpec, Awaitable
from functools import wraps

from assisted_service_client.rest import ApiException
from assisted_service_mcp.src.logger import log


class AssistedServiceAPIError(Exception):
    """Exception for Assisted Service API errors."""


# Type variables for the decorator
P = ParamSpec("P")
T = TypeVar("T")


def sanitize_exceptions(func: Callable[P, Awaitable[T]]) -> Callable[P, Awaitable[T]]:
    """
    Decorate a function to sanitize exceptions from API calls.

    The operation name for logging is automatically derived from the function name.
    For 4xx status codes, the response body is included in the exception message
    to provide more detailed error information.

    Returns:
        Decorated function that catches and sanitizes exceptions
    """

    @wraps(func)
    async def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
        operation_name = func.__name__
        try:
            return await func(*args, **kwargs)
        except ApiException as e:
            log.error(
                "API error during %s: Status: %s, Reason: %s, Body: %s",
                operation_name,
                e.status,
                e.reason,
                e.body,
            )

            error_msg = f"API error: Status {e.status}"
            if e.status and 400 <= e.status <= 499 and e.body:
                error_msg += f", Details: {e.body}"
            raise AssistedServiceAPIError(error_msg) from e
        except Exception as e:
            log.error("Unexpected error during %s: %s", operation_name, str(e))
            raise AssistedServiceAPIError("An internal error occurred") from e

    return wrapper
