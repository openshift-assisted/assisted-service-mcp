"""
Unit tests for the service_client.helpers module.
"""

import pytest
from assisted_service_mcp.src.service_client.helpers import Helpers


class TestHelpers:
    """Test cases for the Helpers class."""

    @pytest.mark.asyncio
    async def test_get_platform_model_default(self) -> None:
        """Test get_platform_model with None or empty string returns baremetal."""
        # Test with None
        platform = Helpers.get_platform_model(None)
        assert platform.type == "baremetal"
        assert platform.external is None

        # Test with empty string
        platform = Helpers.get_platform_model("")
        assert platform.type == "baremetal"
        assert platform.external is None

    @pytest.mark.asyncio
    async def test_get_platform_model_oci(self) -> None:
        """Test get_platform_model with oci platform."""
        platform = Helpers.get_platform_model("oci")
        assert platform.type == "external"
        assert platform.external is not None
        assert platform.external.platform_name == "oci"
        assert platform.external.cloud_controller_manager == "External"

    @pytest.mark.asyncio
    async def test_get_platform_model_valid_platforms(self) -> None:
        """Test get_platform_model with valid platform types."""
        valid_platforms = ["baremetal", "vsphere", "nutanix", "none"]
        for platform_type in valid_platforms:
            platform = Helpers.get_platform_model(platform_type)
            assert platform.type == platform_type
            assert platform.external is None

    @pytest.mark.asyncio
    async def test_get_platform_model_invalid_platform(self) -> None:
        """Test get_platform_model with invalid platform raises ValueError."""
        with pytest.raises(ValueError) as err:
            Helpers.get_platform_model("invalid_platform")
        assert str(err.value) == "Invalid platform invalid_platform"
