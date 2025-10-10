"""Helper functions for the service client."""

from typing import Literal, Optional, cast, get_args
from assisted_service_client import models


class Helpers:
    """Helpers contains functions that can be used by the service client."""

    # Valid platform types for cluster creation and updates
    VALID_PLATFORMS = Literal["baremetal", "vsphere", "oci", "nutanix", "none"]

    @staticmethod
    def get_platform_model(platform: Optional[str]) -> models.Platform:
        """
        Get the platform object from a platform type string.

        Args:
            platform (Optional[str]): The platform type string, or None for default (baremetal)

        Returns:
            models.Platform: The platform object

        Raises:
            ValueError: If the platform is invalid.
        """
        if platform is None or platform == "":
            return models.Platform(type=cast(models.PlatformType, "baremetal"))
        if platform == "oci":
            return models.Platform(
                type=cast(models.PlatformType, "external"),
                external=models.PlatformExternal(
                    platform_name="oci", cloud_controller_manager="External"
                ),
            )
        if platform not in get_args(Helpers.VALID_PLATFORMS):
            raise ValueError(f"Invalid platform {platform}")
        return models.Platform(type=cast(models.PlatformType, platform))
