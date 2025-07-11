"""
Unit tests for the server module.
"""

import json
import os
from typing import Generator, Tuple
from unittest.mock import Mock, patch

import pytest
from requests.exceptions import RequestException

from service_client import InventoryClient
import server
from tests.test_utils import (
    create_test_cluster,
    create_test_installing_cluster,
    create_test_host,
    create_test_infra_env,
    create_test_presigned_url,
)


class TestTokenFunctions:
    """Test cases for token handling functions."""

    @pytest.fixture
    def mock_mcp_get_context(self) -> Generator[Tuple[Mock, Mock], None, None]:
        """Mock MCP context for testing."""
        mock_context = Mock()
        mock_request = Mock()
        mock_context.request_context.request = mock_request

        with patch.object(server.mcp, "get_context", return_value=mock_context):
            yield mock_context, mock_request

    def test_get_offline_token_from_environment(self) -> None:
        """Test retrieving offline token from environment variables."""
        test_token = "test-offline-token"
        with patch.dict(os.environ, {"OFFLINE_TOKEN": test_token}):
            result = server.get_offline_token()
            assert result == test_token

    def test_get_offline_token_environment_takes_precedence(
        self, mock_mcp_get_context: Tuple[Mock, Mock]
    ) -> None:
        """Test that environment token takes precedence over request header token."""
        _mock_context, mock_request = mock_mcp_get_context
        env_token = "environment-token"
        header_token = "header-token"

        # Set up both environment and header tokens
        mock_request.headers.get.return_value = header_token

        with patch.dict(os.environ, {"OFFLINE_TOKEN": env_token}):
            result = server.get_offline_token()

            # Should return the environment token, not the header token
            assert result == env_token

            # Should not even check the request headers since env token was found
            mock_request.headers.get.assert_not_called()

    def test_get_offline_token_from_headers(
        self, mock_mcp_get_context: Tuple[Mock, Mock]
    ) -> None:
        """Test retrieving offline token from request headers."""
        _mock_context, mock_request = mock_mcp_get_context
        test_token = "test-offline-token-header"
        mock_request.headers.get.return_value = test_token

        # Ensure environment variable is not set
        with patch.dict(os.environ, {}, clear=True):
            result = server.get_offline_token()
            assert result == test_token
            mock_request.headers.get.assert_called_once_with("OCM-Offline-Token")

    def test_get_offline_token_not_found(
        self, mock_mcp_get_context: Tuple[Mock, Mock]
    ) -> None:
        """Test error when offline token is not found."""
        _mock_context, mock_request = mock_mcp_get_context
        mock_request.headers.get.return_value = None

        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(RuntimeError) as exc_info:
                server.get_offline_token()
            assert "No offline token found" in str(exc_info.value)

    def test_get_offline_token_no_request(self) -> None:
        """Test offline token retrieval when no request is available."""
        mock_context = Mock()
        mock_context.request_context.request = None

        with patch.object(server.mcp, "get_context", return_value=mock_context):
            with patch.dict(os.environ, {}, clear=True):
                with pytest.raises(RuntimeError) as exc_info:
                    server.get_offline_token()
                assert "No offline token found" in str(exc_info.value)

    def test_get_access_token_from_authorization_header(
        self, mock_mcp_get_context: Tuple[Mock, Mock]
    ) -> None:
        """Test retrieving access token from Authorization header."""
        _mock_context, mock_request = mock_mcp_get_context
        test_token = "test-access-token"
        mock_request.headers.get.return_value = f"Bearer {test_token}"

        result = server.get_access_token()
        assert result == test_token
        mock_request.headers.get.assert_called_once_with("Authorization")

    def test_get_access_token_invalid_authorization_header(
        self, mock_mcp_get_context: Tuple[Mock, Mock]
    ) -> None:
        """Test access token retrieval with invalid Authorization header."""
        _mock_context, mock_request = mock_mcp_get_context
        mock_request.headers.get.return_value = "Invalid header format"

        with patch.object(server, "get_offline_token", return_value="offline-token"):
            with patch("requests.post") as mock_post:
                mock_response = Mock()
                mock_response.json.return_value = {"access_token": "new-token"}
                mock_post.return_value = mock_response

                result = server.get_access_token()
                assert result == "new-token"

    def test_get_access_token_no_authorization_header(
        self, mock_mcp_get_context: Tuple[Mock, Mock]
    ) -> None:
        """Test access token retrieval without Authorization header."""
        _mock_context, mock_request = mock_mcp_get_context
        mock_request.headers.get.return_value = None

        with patch.object(server, "get_offline_token", return_value="offline-token"):
            with patch("requests.post") as mock_post:
                mock_response = Mock()
                mock_response.json.return_value = {"access_token": "new-token"}
                mock_post.return_value = mock_response

                result = server.get_access_token()
                assert result == "new-token"

    @patch("requests.post")
    def test_get_access_token_generate_from_offline_token(
        self, mock_post: Mock, mock_mcp_get_context: Tuple[Mock, Mock]
    ) -> None:
        """Test generating access token from offline token."""
        _mock_context, mock_request = mock_mcp_get_context
        mock_request.headers.get.return_value = None

        offline_token = "test-offline-token"
        access_token = "generated-access-token"

        mock_response = Mock()
        mock_response.json.return_value = {"access_token": access_token}
        mock_post.return_value = mock_response

        with patch.object(server, "get_offline_token", return_value=offline_token):
            result = server.get_access_token()

            assert result == access_token
            mock_post.assert_called_once_with(
                "https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/token",
                data={
                    "client_id": "cloud-services",
                    "grant_type": "refresh_token",
                    "refresh_token": offline_token,
                },
                timeout=30,
            )

    @patch("requests.post")
    def test_get_access_token_custom_sso_url(
        self, mock_post: Mock, mock_mcp_get_context: Tuple[Mock, Mock]
    ) -> None:
        """Test access token generation with custom SSO URL."""
        _mock_context, mock_request = mock_mcp_get_context
        mock_request.headers.get.return_value = None

        custom_sso_url = "https://custom-sso.example.com/token"
        offline_token = "test-offline-token"
        access_token = "generated-access-token"

        mock_response = Mock()
        mock_response.json.return_value = {"access_token": access_token}
        mock_post.return_value = mock_response

        with patch.dict(os.environ, {"SSO_URL": custom_sso_url}):
            with patch.object(server, "get_offline_token", return_value=offline_token):
                result = server.get_access_token()

                assert result == access_token
                mock_post.assert_called_once_with(
                    custom_sso_url,
                    data={
                        "client_id": "cloud-services",
                        "grant_type": "refresh_token",
                        "refresh_token": offline_token,
                    },
                    timeout=30,
                )

    @patch("requests.post")
    def test_get_access_token_request_failure(
        self, mock_post: Mock, mock_mcp_get_context: Tuple[Mock, Mock]
    ) -> None:
        """Test access token generation request failure."""
        _mock_context, mock_request = mock_mcp_get_context
        mock_request.headers.get.return_value = None

        mock_post.side_effect = RequestException("Network error")

        with patch.object(server, "get_offline_token", return_value="offline-token"):
            with pytest.raises(RequestException):
                server.get_access_token()

    def test_get_access_token_no_request_context(self) -> None:
        """Test access token retrieval when no request context is available."""
        mock_context = Mock()
        mock_context.request_context.request = None

        with patch.object(server.mcp, "get_context", return_value=mock_context):
            with patch.object(
                server, "get_offline_token", return_value="offline-token"
            ):
                with patch("requests.post") as mock_post:
                    mock_response = Mock()
                    mock_response.json.return_value = {"access_token": "new-token"}
                    mock_post.return_value = mock_response

                    result = server.get_access_token()
                    assert result == "new-token"


class TestMCPToolFunctions:
    """Test cases for MCP tool functions."""

    @pytest.fixture
    def mock_inventory_client(self) -> Mock:
        """Mock InventoryClient for testing."""
        return Mock(spec=InventoryClient)

    @pytest.fixture
    def mock_get_access_token(self) -> Generator[None, None, None]:
        """Mock get_access_token function."""
        with patch.object(server, "get_access_token", return_value="test-access-token"):
            yield

    @pytest.mark.asyncio
    async def test_cluster_info_success(
        self,
        mock_inventory_client: Mock,
        mock_get_access_token: None,  # pylint: disable=unused-argument
    ) -> None:
        """Test successful cluster_info function."""
        cluster_id = "test-cluster-id"
        cluster = create_test_cluster(cluster_id=cluster_id)
        mock_inventory_client.get_cluster.return_value = cluster

        with patch.object(
            server, "InventoryClient", return_value=mock_inventory_client
        ):
            result = await server.cluster_info(cluster_id)

            assert result == cluster.to_str()
            mock_inventory_client.get_cluster.assert_called_once_with(
                cluster_id=cluster_id
            )

    @pytest.mark.asyncio
    async def test_list_clusters_success(
        self,
        mock_inventory_client: Mock,
        mock_get_access_token: None,  # pylint: disable=unused-argument
    ) -> None:
        """Test successful list_clusters function."""
        mock_clusters = [
            {
                "name": "cluster1",
                "id": "id1",
                "openshift_version": "4.18.2",
                "status": "ready",
            },
            {
                "name": "cluster2",
                "id": "id2",
                "openshift_version": "4.17.1",
                "status": "installing",
            },
        ]
        mock_inventory_client.list_clusters.return_value = mock_clusters

        with patch.object(
            server, "InventoryClient", return_value=mock_inventory_client
        ):
            result = await server.list_clusters()

            expected_result = json.dumps(mock_clusters)
            assert result == expected_result
            mock_inventory_client.list_clusters.assert_called_once()

    @pytest.mark.asyncio
    async def test_cluster_events_success(
        self,
        mock_inventory_client: Mock,
        mock_get_access_token: None,  # pylint: disable=unused-argument
    ) -> None:
        """Test successful cluster_events function."""
        cluster_id = "test-cluster-id"
        mock_events = '{"events": ["event1", "event2"]}'
        mock_inventory_client.get_events.return_value = mock_events

        with patch.object(
            server, "InventoryClient", return_value=mock_inventory_client
        ):
            result = await server.cluster_events(cluster_id)

            assert result == mock_events
            mock_inventory_client.get_events.assert_called_once_with(
                cluster_id=cluster_id
            )

    @pytest.mark.asyncio
    async def test_host_events_success(
        self,
        mock_inventory_client: Mock,
        mock_get_access_token: None,  # pylint: disable=unused-argument
    ) -> None:
        """Test successful host_events function."""
        cluster_id = "test-cluster-id"
        host_id = "test-host-id"
        mock_events = '{"events": ["host-event1", "host-event2"]}'
        mock_inventory_client.get_events.return_value = mock_events

        with patch.object(
            server, "InventoryClient", return_value=mock_inventory_client
        ):
            result = await server.host_events(cluster_id, host_id)

            assert result == mock_events
            mock_inventory_client.get_events.assert_called_once_with(
                cluster_id=cluster_id, host_id=host_id
            )

    @pytest.mark.asyncio
    async def test_cluster_iso_download_url_success(
        self,
        mock_inventory_client: Mock,
        mock_get_access_token: None,  # pylint: disable=unused-argument
    ) -> None:
        """Test successful cluster_iso_download_url function with single infraenv."""
        cluster_id = "test-cluster-id"
        mock_infraenv = {
            "name": "test-infraenv",
            "id": "test-infraenv-id",
            "cluster_id": cluster_id,
            "openshift_version": "4.18.2",
            "download_url": "https://api.openshift.com/api/assisted-install/v2/infra-envs/test-id/downloads/image",
        }
        mock_inventory_client.list_infra_envs.return_value = [mock_infraenv]

        with patch.object(
            server, "InventoryClient", return_value=mock_inventory_client
        ):
            result = await server.cluster_iso_download_url(cluster_id)

            expected_result = "https://api.openshift.com/api/assisted-install/v2/infra-envs/test-id/downloads/image"
            assert result == expected_result
            mock_inventory_client.list_infra_envs.assert_called_once_with(cluster_id)

    @pytest.mark.asyncio
    async def test_cluster_iso_download_url_multiple_infraenvs(
        self,
        mock_inventory_client: Mock,
        mock_get_access_token: None,  # pylint: disable=unused-argument
    ) -> None:
        """Test successful cluster_iso_download_url function with multiple infraenvs."""
        cluster_id = "test-cluster-id"

        # First infraenv
        mock_infraenv1 = {
            "name": "test-infraenv-1",
            "id": "test-infraenv-id-1",
            "cluster_id": cluster_id,
            "openshift_version": "4.18.2",
            "download_url": "https://api.openshift.com/api/assisted-install/v2/infra-envs/test-id-1/downloads/image",
        }

        # Second infraenv with different characteristics
        mock_infraenv2 = {
            "name": "test-infraenv-2",
            "id": "test-infraenv-id-2",
            "cluster_id": cluster_id,
            "openshift_version": "4.18.2",
            "download_url": "https://api.openshift.com/api/assisted-install/v2/infra-envs/test-id-2/downloads/image",
        }

        mock_inventory_client.list_infra_envs.return_value = [
            mock_infraenv1,
            mock_infraenv2,
        ]

        with patch.object(
            server, "InventoryClient", return_value=mock_inventory_client
        ):
            result = await server.cluster_iso_download_url(cluster_id)

            expected_result = (
                "https://api.openshift.com/api/assisted-install/v2/infra-envs/test-id-1/downloads/image\n"
                "https://api.openshift.com/api/assisted-install/v2/infra-envs/test-id-2/downloads/image"
            )
            assert result == expected_result
            mock_inventory_client.list_infra_envs.assert_called_once_with(cluster_id)

    @pytest.mark.asyncio
    async def test_cluster_iso_download_url_no_infraenvs(
        self,
        mock_inventory_client: Mock,
        mock_get_access_token: None,  # pylint: disable=unused-argument
    ) -> None:
        """Test cluster_iso_download_url function when no infraenvs are found."""
        cluster_id = "test-cluster-id"
        mock_inventory_client.list_infra_envs.return_value = []

        with patch.object(
            server, "InventoryClient", return_value=mock_inventory_client
        ):
            result = await server.cluster_iso_download_url(cluster_id)

            assert result == "No ISO download URLs found for this cluster."
            mock_inventory_client.list_infra_envs.assert_called_once_with(cluster_id)

    @pytest.mark.asyncio
    async def test_create_cluster_success(
        self,
        mock_inventory_client: Mock,
        mock_get_access_token: None,  # pylint: disable=unused-argument
    ) -> None:
        """Test successful create_cluster function."""
        name = "test-cluster"
        version = "4.18.2"
        base_domain = "example.com"
        single_node = False

        cluster = create_test_cluster(
            cluster_id="cluster-id",
            name=name,
            openshift_version=version,
        )
        infraenv = create_test_infra_env(
            infra_env_id="infraenv-id",
            name=name,
        )

        mock_inventory_client.create_cluster.return_value = cluster
        mock_inventory_client.create_infra_env.return_value = infraenv

        with patch.object(
            server, "InventoryClient", return_value=mock_inventory_client
        ):
            result = await server.create_cluster(
                name, version, base_domain, single_node
            )
            assert result == cluster.id

            mock_inventory_client.create_cluster.assert_called_once_with(
                name, version, single_node, base_dns_domain=base_domain, tags="chatbot"
            )
            mock_inventory_client.create_infra_env.assert_called_once_with(
                name, cluster_id="cluster-id", openshift_version=version
            )

    @pytest.mark.asyncio
    async def test_set_cluster_vips_success(
        self,
        mock_inventory_client: Mock,
        mock_get_access_token: None,  # pylint: disable=unused-argument
    ) -> None:
        """Test successful set_cluster_vips function."""
        cluster_id = "test-cluster-id"
        api_vip = "192.168.1.100"
        ingress_vip = "192.168.1.101"

        cluster = create_test_cluster(cluster_id=cluster_id)
        mock_inventory_client.update_cluster.return_value = cluster

        with patch.object(
            server, "InventoryClient", return_value=mock_inventory_client
        ):
            result = await server.set_cluster_vips(cluster_id, api_vip, ingress_vip)

            assert result == cluster.to_str()
            mock_inventory_client.update_cluster.assert_called_once_with(
                cluster_id, api_vip=api_vip, ingress_vip=ingress_vip
            )

    @pytest.mark.asyncio
    async def test_install_cluster_success(
        self,
        mock_inventory_client: Mock,
        mock_get_access_token: None,  # pylint: disable=unused-argument
    ) -> None:
        """Test successful install_cluster function."""
        cluster_id = "test-cluster-id"
        cluster = create_test_installing_cluster(cluster_id=cluster_id)
        mock_inventory_client.install_cluster.return_value = cluster

        with patch.object(
            server, "InventoryClient", return_value=mock_inventory_client
        ):
            result = await server.install_cluster(cluster_id)

            assert result == cluster.to_str()
            mock_inventory_client.install_cluster.assert_called_once_with(cluster_id)

    @pytest.mark.asyncio
    async def test_list_versions_success(
        self,
        mock_inventory_client: Mock,
        mock_get_access_token: None,  # pylint: disable=unused-argument
    ) -> None:
        """Test successful list_versions function."""
        mock_versions = {"versions": ["4.18.2", "4.17.1"]}
        mock_inventory_client.get_openshift_versions.return_value = mock_versions

        with patch.object(
            server, "InventoryClient", return_value=mock_inventory_client
        ):
            result = await server.list_versions()

            expected_result = json.dumps(mock_versions)
            assert result == expected_result
            mock_inventory_client.get_openshift_versions.assert_called_once_with(True)

    @pytest.mark.asyncio
    async def test_list_operator_bundles_success(
        self,
        mock_inventory_client: Mock,
        mock_get_access_token: None,  # pylint: disable=unused-argument
    ) -> None:
        """Test successful list_operator_bundles function."""
        mock_bundles = [
            {"name": "bundle1", "operators": ["op1"]},
            {"name": "bundle2", "operators": ["op2"]},
        ]
        mock_inventory_client.get_operator_bundles.return_value = mock_bundles

        with patch.object(
            server, "InventoryClient", return_value=mock_inventory_client
        ):
            result = await server.list_operator_bundles()

            expected_result = json.dumps(mock_bundles)
            assert result == expected_result
            mock_inventory_client.get_operator_bundles.assert_called_once()

    @pytest.mark.asyncio
    async def test_add_operator_bundle_to_cluster_success(
        self,
        mock_inventory_client: Mock,
        mock_get_access_token: None,  # pylint: disable=unused-argument
    ) -> None:
        """Test successful add_operator_bundle_to_cluster function."""
        cluster_id = "test-cluster-id"
        bundle_name = "test-bundle"

        cluster = create_test_cluster(cluster_id=cluster_id)
        mock_inventory_client.add_operator_bundle_to_cluster.return_value = cluster

        with patch.object(
            server, "InventoryClient", return_value=mock_inventory_client
        ):
            result = await server.add_operator_bundle_to_cluster(
                cluster_id, bundle_name
            )

            assert result == cluster.to_str()
            mock_inventory_client.add_operator_bundle_to_cluster.assert_called_once_with(
                cluster_id, bundle_name
            )

    @pytest.mark.asyncio
    async def test_set_host_role_success(
        self,
        mock_inventory_client: Mock,
        mock_get_access_token: None,  # pylint: disable=unused-argument
    ) -> None:
        """Test successful set_host_role function."""
        host_id = "test-host-id"
        infraenv_id = "test-infraenv-id"
        role = "master"

        host = create_test_host(host_id=host_id, role=role)
        mock_inventory_client.update_host.return_value = host

        with patch.object(
            server, "InventoryClient", return_value=mock_inventory_client
        ):
            result = await server.set_host_role(host_id, infraenv_id, role)

            assert result == host.to_str()
            mock_inventory_client.update_host.assert_called_once_with(
                host_id, infraenv_id, host_role=role
            )

    @pytest.mark.asyncio
    async def test_cluster_credentials_download_url_success(
        self,
        mock_inventory_client: Mock,
        mock_get_access_token: None,  # pylint: disable=unused-argument
    ) -> None:
        """Test successful cluster_credentials_download_url function."""
        cluster_id = "test-cluster-id"
        file_name = "kubeconfig"

        presigned_url = create_test_presigned_url()
        mock_inventory_client.get_presigned_for_cluster_credentials.return_value = (
            presigned_url
        )

        with patch.object(
            server, "InventoryClient", return_value=mock_inventory_client
        ):
            result = await server.cluster_credentials_download_url(
                cluster_id, file_name
            )

            expected_result = "URL: https://example.com/presigned-url\nExpires at: 2023-12-31T23:59:59Z"
            assert result == expected_result
            mock_inventory_client.get_presigned_for_cluster_credentials.assert_called_once_with(
                cluster_id, file_name
            )

    @pytest.mark.asyncio
    async def test_cluster_credentials_download_url_no_expiration(
        self,
        mock_inventory_client: Mock,
        mock_get_access_token: None,  # pylint: disable=unused-argument
    ) -> None:
        """Test cluster_credentials_download_url function when no expiration is provided."""
        cluster_id = "test-cluster-id"
        file_name = "kubeconfig"

        presigned_url = create_test_presigned_url(expires_at=None)
        mock_inventory_client.get_presigned_for_cluster_credentials.return_value = (
            presigned_url
        )

        with patch.object(
            server, "InventoryClient", return_value=mock_inventory_client
        ):
            result = await server.cluster_credentials_download_url(
                cluster_id, file_name
            )

            expected_result = "URL: https://example.com/presigned-url"
            assert result == expected_result
            mock_inventory_client.get_presigned_for_cluster_credentials.assert_called_once_with(
                cluster_id, file_name
            )

    @pytest.mark.asyncio
    async def test_cluster_credentials_download_url_zero_expiration(
        self,
        mock_inventory_client: Mock,
        mock_get_access_token: None,  # pylint: disable=unused-argument
    ) -> None:
        """Test cluster_credentials_download_url function when expiration is a zero/default date."""
        cluster_id = "test-cluster-id"
        file_name = "kubeconfig"

        presigned_url = create_test_presigned_url(
            expires_at="0001-01-01 00:00:00+00:00",
        )
        mock_inventory_client.get_presigned_for_cluster_credentials.return_value = (
            presigned_url
        )

        with patch.object(
            server, "InventoryClient", return_value=mock_inventory_client
        ):
            result = await server.cluster_credentials_download_url(
                cluster_id, file_name
            )

            # Should not include expiration time since it's a zero/default value
            expected_result = "URL: https://example.com/presigned-url"
            assert result == expected_result
            mock_inventory_client.get_presigned_for_cluster_credentials.assert_called_once_with(
                cluster_id, file_name
            )
