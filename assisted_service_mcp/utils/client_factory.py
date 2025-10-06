"""Client factory for creating InventoryClient instances.

This module provides a centralized way to create InventoryClient instances,
making it easier to mock in tests.
"""

import sys
from service_client import InventoryClient as _BaseInventoryClient


def InventoryClient(access_token: str):
    """Create an InventoryClient with the given access token.
    
    This function checks if server.InventoryClient has been mocked (for testing)
    and uses that if available, otherwise uses the real client.
    
    Args:
        access_token: The access token for authentication.
        
    Returns:
        InventoryClient: A new InventoryClient instance.
    """
    # Check if we're being called from tests that have mocked server.InventoryClient
    if 'server' in sys.modules:
        server_module = sys.modules['server']
        if hasattr(server_module, 'InventoryClient'):
            # Use the potentially-mocked version from server
            server_client = server_module.InventoryClient
            # If it's been mocked by tests, it will be a Mock/function that returns a mock
            if callable(server_client) and server_client != InventoryClient:
                return server_client(access_token)
    
    # Default: use the real client
    return _BaseInventoryClient(access_token)

