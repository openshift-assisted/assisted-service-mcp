"""
Service client package for Red Hat Assisted Service API.

This package provides client classes and utilities for interacting with
Red Hat's Assisted Service API to manage OpenShift cluster installations.
"""

from assisted_service_mcp.src.logger import log
from .assisted_service_api import InventoryClient

__all__ = ["InventoryClient", "log"]
