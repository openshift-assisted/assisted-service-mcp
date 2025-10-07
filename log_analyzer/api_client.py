"""
API client for fetching logs from OpenShift Assisted Installer API.
"""

import logging
from typing import Optional, Dict, Any

import requests
import nestedarchive

logger = logging.getLogger(__name__)


class AssistedInstallerAPIClient:
    """Client for interacting with the OpenShift Assisted Installer API."""

    def __init__(
        self,
        base_url: str = "https://api.openshift.com",
        auth_token: Optional[str] = None,
    ):
        """
        Initialize the API client.

        Args:
            base_url: Base URL for the API
            auth_token: Authentication token if required
        """
        self.base_url = base_url.rstrip("/")
        self.auth_token = auth_token
        self.session = requests.Session()

        if auth_token:
            self.session.headers.update({"Authorization": f"Bearer {auth_token}"})

    def get_logs_download_url(self, cluster_id: str) -> Dict[str, Any]:
        """
        Get the presigned URL for downloading cluster logs.

        Args:
            cluster_id: UUID of the cluster

        Returns:
            Dictionary with 'url' and 'expires_at' fields

        Raises:
            requests.RequestException: If the API request fails
        """
        url = f"{self.base_url}/api/assisted-install/v2/clusters/{cluster_id}/downloads/files-presigned"
        params = {"file_name": "logs"}

        logger.info("Fetching presigned URL for cluster %s", cluster_id)
        response = self.session.get(url, params=params)
        response.raise_for_status()

        return response.json()

    def download_logs(self, cluster_id: str) -> nestedarchive.RemoteNestedArchive:
        """
        Download logs for a cluster and return a nested archive handler.

        Args:
            cluster_id: UUID of the cluster

        Returns:
            RemoteNestedArchive object for accessing the logs

        Raises:
            requests.RequestException: If download fails
        """
        # Get the presigned URL
        download_info = self.get_logs_download_url(cluster_id)
        logs_url = download_info["url"]

        logger.info("Downloading logs from %s", logs_url)

        # Create a RemoteNestedArchive from the presigned URL
        return nestedarchive.RemoteNestedArchive(logs_url, init_download=True)
