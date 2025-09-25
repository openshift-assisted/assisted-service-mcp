"""
Unit tests for the assisted_service_api module.
"""

import os
from unittest.mock import Mock, patch

import pytest
from requests.exceptions import RequestException
from assisted_service_client.rest import ApiException
from assisted_service_client import Configuration, models

from service_client.assisted_service_api import InventoryClient
from service_client.exceptions import AssistedServiceAPIError
from tests.test_utils import (
    create_test_cluster,
    create_test_installing_cluster,
    create_test_host,
    create_test_infra_env,
    create_test_presigned_url,
)


class TestInventoryClient:  # pylint: disable=too-many-public-methods
    """Test cases for the InventoryClient class."""

    @pytest.fixture
    def mock_access_token(self) -> str:
        """Mock access token for testing."""
        return "test-access-token"

    @pytest.fixture
    def client(self, mock_access_token: str) -> InventoryClient:
        """Create a test client instance."""
        with patch.object(
            InventoryClient, "_get_pull_secret", return_value="test-pull-secret"
        ):
            return InventoryClient(mock_access_token)

    @pytest.fixture
    def mock_api_client(self) -> Mock:
        """Mock API client for testing."""
        return Mock()

    def test_init_with_access_token(self, mock_access_token: str) -> None:
        """Test client initialization with access token."""
        with patch.object(
            InventoryClient, "_get_pull_secret", return_value="test-pull-secret"
        ):
            client = InventoryClient(mock_access_token)
            assert client.access_token == mock_access_token
            assert client.pull_secret == "test-pull-secret"
            assert (
                client.inventory_url
                == "https://api.openshift.com/api/assisted-install/v2"
            )
            assert client.client_debug is False

    def test_init_with_environment_variables(self, mock_access_token: str) -> None:
        """Test client initialization with environment variables."""
        test_url = "https://custom-api.example.com/v2"
        with patch.dict(
            os.environ, {"INVENTORY_URL": test_url, "CLIENT_DEBUG": "true"}
        ):
            with patch.object(
                InventoryClient, "_get_pull_secret", return_value="test-pull-secret"
            ):
                client = InventoryClient(mock_access_token)
                assert client.inventory_url == test_url
                assert client.client_debug is True

    @patch("requests.post")
    def test_get_pull_secret_success(
        self, mock_post: Mock, mock_access_token: str
    ) -> None:
        """Test successful pull secret retrieval."""
        mock_response = Mock()
        mock_response.text = "pull-secret-content"
        mock_post.return_value = mock_response

        client = InventoryClient(mock_access_token)

        # Access the pull_secret property to trigger lazy loading
        pull_secret = client.pull_secret

        mock_post.assert_called_once_with(
            "https://api.openshift.com/api/accounts_mgmt/v1/access_token",
            headers={"Authorization": f"Bearer {mock_access_token}"},
            timeout=30,
        )
        assert pull_secret == "pull-secret-content"

    @patch("requests.post")
    def test_get_pull_secret_failure(
        self, mock_post: Mock, mock_access_token: str
    ) -> None:
        """Test pull secret retrieval failure."""
        mock_post.side_effect = RequestException("Network error")

        client = InventoryClient(mock_access_token)

        # Exception should be raised when accessing pull_secret property
        with pytest.raises(RequestException):
            _ = client.pull_secret

    @patch("requests.post")
    def test_get_pull_secret_with_custom_url(
        self, mock_post: Mock, mock_access_token: str
    ) -> None:
        """Test pull secret retrieval with custom URL."""
        custom_url = "https://custom-pull-secret.example.com"
        mock_response = Mock()
        mock_response.text = "pull-secret-content"
        mock_post.return_value = mock_response

        with patch.dict(os.environ, {"PULL_SECRET_URL": custom_url}):
            client = InventoryClient(mock_access_token)

            # Access the pull_secret property to trigger lazy loading
            _ = client.pull_secret

            mock_post.assert_called_once_with(
                custom_url,
                headers={"Authorization": f"Bearer {mock_access_token}"},
                timeout=30,
            )

    def test_get_host_url_parsing(self, client: InventoryClient) -> None:
        """Test URL parsing and host replacement."""
        configs = Configuration()
        configs.host = "https://original.example.com/api/v1"
        client.inventory_url = "https://custom.example.com/api/assisted-install/v2"

        result = client._get_host(configs)  # pylint: disable=protected-access

        # The method replaces the netloc and scheme but keeps the original path
        assert result == "https://custom.example.com/api/v1"

    @patch("service_client.assisted_service_api.ApiClient")
    def test_get_client_configuration(
        self, mock_api_client_class: Mock, client: InventoryClient
    ) -> None:
        """Test API client configuration."""
        mock_api_client = Mock()
        mock_api_client_class.return_value = mock_api_client

        result = client._get_client()  # pylint: disable=protected-access

        assert result == mock_api_client
        # Verify configuration was set up correctly
        _args, kwargs = mock_api_client_class.call_args
        config = kwargs["configuration"]
        assert config.api_key_prefix["Authorization"] == "Bearer"
        assert config.api_key["Authorization"] == client.access_token

    @pytest.mark.asyncio
    async def test_get_cluster_success(self, client: InventoryClient) -> None:
        """Test successful cluster retrieval."""
        cluster_id = "test-cluster-id"
        cluster = create_test_cluster(cluster_id=cluster_id)

        with patch.object(client, "_installer_api") as mock_installer_api:
            mock_api = Mock()
            mock_api.v2_get_cluster.return_value = cluster
            mock_installer_api.return_value = mock_api

            result = await client.get_cluster(cluster_id)

            assert result == cluster
            mock_api.v2_get_cluster.assert_called_once_with(
                cluster_id=cluster_id, get_unregistered_clusters=False
            )

    @pytest.mark.asyncio
    async def test_get_cluster_with_unregistered(self, client: InventoryClient) -> None:
        """Test cluster retrieval with unregistered clusters."""
        cluster_id = "test-cluster-id"
        cluster = create_test_cluster(cluster_id=cluster_id)

        with patch.object(client, "_installer_api") as mock_installer_api:
            mock_api = Mock()
            mock_api.v2_get_cluster.return_value = cluster
            mock_installer_api.return_value = mock_api

            result = await client.get_cluster(
                cluster_id, get_unregistered_clusters=True
            )

            assert result == cluster
            mock_api.v2_get_cluster.assert_called_once_with(
                cluster_id=cluster_id, get_unregistered_clusters=True
            )

    @pytest.mark.asyncio
    async def test_get_cluster_api_exception(self, client: InventoryClient) -> None:
        """Test cluster retrieval API exception handling with 4xx error body details."""
        cluster_id = "test-cluster-id"

        with patch.object(client, "_installer_api") as mock_installer_api:
            mock_api = Mock()
            # Create a mock HTTP response with body data
            mock_http_resp = Mock()
            mock_http_resp.status = 404
            mock_http_resp.reason = "Not Found"
            mock_http_resp.data = (
                '{"message": "Cluster not found", "code": "CLUSTER_NOT_FOUND"}'
            )
            mock_http_resp.getheaders.return_value = {}

            mock_api.v2_get_cluster.side_effect = ApiException(http_resp=mock_http_resp)
            mock_installer_api.return_value = mock_api

            with pytest.raises(AssistedServiceAPIError) as exc_info:
                await client.get_cluster(cluster_id)

            error_message = str(exc_info.value)
            assert "API error: Status 404" in error_message
            assert (
                'Details: {"message": "Cluster not found", "code": "CLUSTER_NOT_FOUND"}'
                in error_message
            )

    @pytest.mark.asyncio
    async def test_get_cluster_unexpected_exception(
        self, client: InventoryClient
    ) -> None:
        """Test cluster retrieval unexpected exception handling."""
        cluster_id = "test-cluster-id"

        with patch.object(client, "_installer_api") as mock_installer_api:
            mock_api = Mock()
            mock_api.v2_get_cluster.side_effect = ValueError("Unexpected error")
            mock_installer_api.return_value = mock_api

            with pytest.raises(AssistedServiceAPIError) as exc_info:
                await client.get_cluster(cluster_id)

            assert "An internal error occurred" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_list_clusters_success(self, client: InventoryClient) -> None:
        """Test successful cluster listing."""
        mock_clusters = [{"id": "cluster1"}, {"id": "cluster2"}]

        with patch.object(client, "_installer_api") as mock_installer_api:
            mock_api = Mock()
            mock_api.v2_list_clusters.return_value = mock_clusters
            mock_installer_api.return_value = mock_api

            result = await client.list_clusters()

            assert result == mock_clusters
            mock_api.v2_list_clusters.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_events_success(self, client: InventoryClient) -> None:
        """Test successful event retrieval."""
        cluster_id = "test-cluster-id"
        mock_events = '{"events": ["event1", "event2"]}'

        with patch.object(client, "_events_api") as mock_events_api:
            mock_api = Mock()
            mock_response = Mock()
            mock_response.data = mock_events
            mock_api.v2_list_events.return_value = mock_response
            mock_events_api.return_value = mock_api

            result = await client.get_events(cluster_id=cluster_id)

            assert result == mock_events
            mock_api.v2_list_events.assert_called_once_with(
                cluster_id=cluster_id,
                host_id="",
                infra_env_id="",
                categories=["user"],
                _preload_content=False,
            )

    @pytest.mark.asyncio
    async def test_get_events_with_custom_categories(
        self, client: InventoryClient
    ) -> None:
        """Test event retrieval with custom categories."""
        cluster_id = "test-cluster-id"
        categories = ["system", "user"]
        mock_events = '{"events": []}'

        with patch.object(client, "_events_api") as mock_events_api:
            mock_api = Mock()
            mock_response = Mock()
            mock_response.data = mock_events
            mock_api.v2_list_events.return_value = mock_response
            mock_events_api.return_value = mock_api

            result = await client.get_events(
                cluster_id=cluster_id, categories=categories
            )

            assert result == mock_events
            mock_api.v2_list_events.assert_called_once_with(
                cluster_id=cluster_id,
                host_id="",
                infra_env_id="",
                categories=categories,
                _preload_content=False,
            )

    @pytest.mark.asyncio
    async def test_get_infra_env_success(self, client: InventoryClient) -> None:
        """Test successful infrastructure environment retrieval."""
        infra_env_id = "test-infra-env-id"
        infra_env = create_test_infra_env(
            infra_env_id=infra_env_id,
            name="test-infra-env",
        )

        with patch.object(client, "_installer_api") as mock_installer_api:
            mock_api = Mock()
            mock_api.get_infra_env.return_value = infra_env
            mock_installer_api.return_value = mock_api

            result = await client.get_infra_env(infra_env_id)

            assert result == infra_env
            mock_api.get_infra_env.assert_called_once_with(infra_env_id=infra_env_id)

    @pytest.mark.asyncio
    async def test_list_infra_envs_success(self, client: InventoryClient) -> None:
        """Test successful infrastructure environments listing for a cluster."""
        cluster_id = "test-cluster-id"
        infra_env1 = create_test_infra_env(
            infra_env_id="infra-env-1",
            name="test-infra-env-1",
        )
        infra_env2 = create_test_infra_env(
            infra_env_id="infra-env-2",
            name="test-infra-env-2",
        )
        infra_envs = [infra_env1, infra_env2]

        with patch.object(client, "_installer_api") as mock_installer_api:
            mock_api = Mock()
            mock_api.list_infra_envs.return_value = infra_envs
            mock_installer_api.return_value = mock_api

            result = await client.list_infra_envs(cluster_id)

            assert result == infra_envs
            assert len(result) == 2
            mock_api.list_infra_envs.assert_called_once_with(cluster_id=cluster_id)

    @pytest.mark.asyncio
    async def test_list_infra_envs_api_exception(self, client: InventoryClient) -> None:
        """Test infrastructure environments listing API exception handling."""
        cluster_id = "test-cluster-id"

        with patch.object(client, "_installer_api") as mock_installer_api:
            mock_api = Mock()
            mock_api.list_infra_envs.side_effect = ApiException(
                status=404, reason="Not Found"
            )
            mock_installer_api.return_value = mock_api

            with pytest.raises(AssistedServiceAPIError) as exc_info:
                await client.list_infra_envs(cluster_id)

            assert "API error: Status 404" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_create_cluster_success(self, client: InventoryClient) -> None:
        """Test successful cluster creation."""
        name = "test-cluster"
        version = "4.18.2"
        single_node = False
        cluster = create_test_cluster(
            cluster_id="test-cluster-id",
            name=name,
            openshift_version=version,
        )

        with (
            patch.object(client, "_installer_api") as mock_installer_api,
            patch.object(client, "_get_pull_secret", return_value="mock-pull-secret"),
        ):
            mock_api = Mock()
            mock_api.v2_register_cluster.return_value = cluster
            mock_installer_api.return_value = mock_api

            result = await client.create_cluster(
                name, version, single_node, base_dns_domain="example.com", platform=""
            )

            assert result == cluster
            mock_api.v2_register_cluster.assert_called_once()
            # Verify the cluster params
            _args, kwargs = mock_api.v2_register_cluster.call_args
            cluster_params = kwargs["new_cluster_params"]
            assert cluster_params.name == name
            assert cluster_params.openshift_version == version
            assert cluster_params.pull_secret == "mock-pull-secret"

    @pytest.mark.asyncio
    async def test_create_cluster_single_node(self, client: InventoryClient) -> None:
        """Test single node cluster creation."""
        name = "test-sno-cluster"
        version = "4.18.2"
        single_node = True
        cluster = create_test_cluster(
            cluster_id="test-sno-cluster-id",
            name=name,
            openshift_version=version,
        )

        with (
            patch.object(client, "_installer_api") as mock_installer_api,
            patch.object(client, "_get_pull_secret", return_value="mock-pull-secret"),
        ):
            mock_api = Mock()
            mock_api.v2_register_cluster.return_value = cluster
            mock_installer_api.return_value = mock_api

            result = await client.create_cluster(
                name, version, single_node, platform="none"
            )

            assert result == cluster
            # Verify single node specific parameters have correct values
            _args, kwargs = mock_api.v2_register_cluster.call_args
            cluster_params = kwargs["new_cluster_params"]
            assert cluster_params.control_plane_count == 1
            assert cluster_params.high_availability_mode == "None"
            assert cluster_params.user_managed_networking is True
            assert cluster_params.platform.type == "none"

    @pytest.mark.asyncio
    async def test_create_infra_env_success(self, client: InventoryClient) -> None:
        """Test successful infrastructure environment creation."""
        name = "test-infra-env"
        infra_env = create_test_infra_env(
            infra_env_id="test-infra-env-id",
            name=name,
        )

        with (
            patch.object(client, "_installer_api") as mock_installer_api,
            patch.object(client, "_get_pull_secret", return_value="mock-pull-secret"),
        ):
            mock_api = Mock()
            mock_api.register_infra_env.return_value = infra_env
            mock_installer_api.return_value = mock_api

            result = await client.create_infra_env(name, cluster_id="test-cluster-id")

            assert result == infra_env
            mock_api.register_infra_env.assert_called_once()
            # Verify the infra env params
            _args, kwargs = mock_api.register_infra_env.call_args
            infra_env_params = kwargs["infraenv_create_params"]
            assert infra_env_params.name == name
            assert infra_env_params.pull_secret == client.pull_secret

    @pytest.mark.asyncio
    async def test_update_infra_env_success(self, client: InventoryClient) -> None:
        """Test successful update_infra_env function."""
        infra_env_id = "test-infra-env-id"
        ssh_key = "ssh-rsa AAAAB3NzaC1yc2E test@example.com"

        infra_env = create_test_infra_env(infra_env_id=infra_env_id)

        with patch.object(
            client, "_installer_api", return_value=Mock()
        ) as mock_api_getter:
            mock_api = mock_api_getter.return_value
            mock_api.update_infra_env.return_value = infra_env

            result = await client.update_infra_env(
                infra_env_id, ssh_authorized_key=ssh_key
            )

            assert result == infra_env
            mock_api.update_infra_env.assert_called_once()

            # Verify the parameters passed to the API
            _args, kwargs = mock_api.update_infra_env.call_args
            assert kwargs["infra_env_id"] == infra_env_id
            update_params = kwargs["infra_env_update_params"]
            assert update_params.ssh_authorized_key == ssh_key

    @pytest.mark.asyncio
    async def test_update_infra_env_api_exception(
        self, client: InventoryClient
    ) -> None:
        """Test update_infra_env function with API exception."""
        infra_env_id = "test-infra-env-id"

        with patch.object(
            client, "_installer_api", return_value=Mock()
        ) as mock_api_getter:
            mock_api = mock_api_getter.return_value
            mock_api.update_infra_env.side_effect = ApiException(
                status=404, reason="Not Found"
            )

            with pytest.raises(AssistedServiceAPIError, match="API error: Status 404"):
                await client.update_infra_env(
                    infra_env_id, ssh_authorized_key="test-key"
                )

    @pytest.mark.asyncio
    async def test_update_cluster_success(self, client: InventoryClient) -> None:
        """Test successful cluster update."""
        cluster_id = "test-cluster-id"
        api_vip = "192.168.1.100"
        ingress_vip = "192.168.1.101"
        cluster = create_test_cluster(cluster_id=cluster_id)

        with patch.object(client, "_installer_api") as mock_installer_api:
            mock_api = Mock()
            mock_api.v2_update_cluster.return_value = cluster
            mock_installer_api.return_value = mock_api

            result = await client.update_cluster(
                cluster_id, api_vip=api_vip, ingress_vip=ingress_vip
            )

            assert result == cluster

            # Verify the call was made with correct cluster_id
            mock_api.v2_update_cluster.assert_called_once()
            _args, kwargs = mock_api.v2_update_cluster.call_args
            assert kwargs["cluster_id"] == cluster_id

            # Verify the cluster_update_params contain the correct VIPs
            cluster_params = kwargs["cluster_update_params"]

            # Check API VIP was set correctly
            assert len(cluster_params.api_vips) == 1
            api_vip_obj = cluster_params.api_vips[0]
            assert api_vip_obj.cluster_id == cluster_id
            assert api_vip_obj.ip == api_vip

            # Check Ingress VIP was set correctly
            assert len(cluster_params.ingress_vips) == 1
            ingress_vip_obj = cluster_params.ingress_vips[0]
            assert ingress_vip_obj.cluster_id == cluster_id
            assert ingress_vip_obj.ip == ingress_vip

    @pytest.mark.asyncio
    async def test_install_cluster_success(self, client: InventoryClient) -> None:
        """Test successful cluster installation."""
        cluster_id = "test-cluster-id"
        cluster = create_test_installing_cluster(cluster_id=cluster_id)

        with patch.object(client, "_installer_api") as mock_installer_api:
            mock_api = Mock()
            mock_api.v2_install_cluster.return_value = cluster
            mock_installer_api.return_value = mock_api

            result = await client.install_cluster(cluster_id)

            assert result == cluster
            mock_api.v2_install_cluster.assert_called_once_with(cluster_id=cluster_id)

    @pytest.mark.asyncio
    async def test_get_openshift_versions_success(
        self, client: InventoryClient
    ) -> None:
        """Test successful OpenShift versions retrieval."""
        versions = models.OpenshiftVersions()

        with patch.object(client, "_versions_api") as mock_versions_api:
            mock_api = Mock()
            mock_api.v2_list_supported_openshift_versions.return_value = versions
            mock_versions_api.return_value = mock_api

            result = await client.get_openshift_versions(only_latest=True)

            assert result == versions
            mock_api.v2_list_supported_openshift_versions.assert_called_once_with(
                only_latest=True
            )

    @pytest.mark.asyncio
    async def test_get_operator_bundles_success(self, client: InventoryClient) -> None:
        """Test successful operator bundles retrieval."""
        mock_bundle1 = Mock()
        mock_bundle1.to_dict.return_value = {"name": "bundle1", "operators": ["op1"]}
        mock_bundle2 = Mock()
        mock_bundle2.to_dict.return_value = {"name": "bundle2", "operators": ["op2"]}
        mock_bundles = [mock_bundle1, mock_bundle2]

        with patch.object(client, "_operators_api") as mock_operators_api:
            mock_api = Mock()
            mock_api.v2_list_bundles.return_value = mock_bundles
            mock_operators_api.return_value = mock_api

            result = await client.get_operator_bundles()

            assert len(result) == 2
            assert result[0] == {"name": "bundle1", "operators": ["op1"]}
            assert result[1] == {"name": "bundle2", "operators": ["op2"]}
            mock_api.v2_list_bundles.assert_called_once()

    @pytest.mark.asyncio
    async def test_add_operator_bundle_to_cluster_success(
        self, client: InventoryClient
    ) -> None:
        """Test successful operator bundle addition to cluster."""
        cluster_id = "test-cluster-id"
        bundle_name = "test-bundle"
        mock_bundle = Mock()
        mock_bundle.operators = ["operator1", "operator2"]
        cluster = create_test_cluster(cluster_id=cluster_id)

        with patch.object(client, "_operators_api") as mock_operators_api:
            with patch.object(client, "update_cluster") as mock_update_cluster:
                mock_api = Mock()
                mock_api.v2_get_bundle.return_value = mock_bundle
                mock_operators_api.return_value = mock_api
                mock_update_cluster.return_value = cluster

                result = await client.add_operator_bundle_to_cluster(
                    cluster_id, bundle_name
                )

                assert result == cluster
                mock_api.v2_get_bundle.assert_called_once_with(bundle_name)

                # Verify update_cluster was called with correct operators
                mock_update_cluster.assert_called_once()
                _args, kwargs = mock_update_cluster.call_args
                assert kwargs["cluster_id"] == cluster_id  # cluster_id is a keyword arg

                # Verify the olm_operators parameter contains the correct operators
                olm_operators = kwargs["olm_operators"]
                assert len(olm_operators) == 2

                # Check that each operator from the bundle was included
                operator_names = [op.name for op in olm_operators]
                assert set(operator_names) == {"operator1", "operator2"}

    @pytest.mark.asyncio
    async def test_update_cluster_platform_success(
        self, client: InventoryClient
    ) -> None:
        """Test successful cluster platform update."""
        cluster_id = "test-cluster-id"
        platform = "vsphere"
        cluster = create_test_cluster(cluster_id=cluster_id)

        with patch.object(client, "_installer_api") as mock_installer_api:
            mock_api = Mock()
            mock_api.v2_update_cluster.return_value = cluster
            mock_installer_api.return_value = mock_api

            result = await client.update_cluster(cluster_id, platform=platform)

            assert result == cluster

            # Verify the call was made with correct cluster_id
            mock_api.v2_update_cluster.assert_called_once()
            _args, kwargs = mock_api.v2_update_cluster.call_args
            assert kwargs["cluster_id"] == cluster_id

            # Verify the cluster_update_params contain platform
            cluster_params = kwargs["cluster_update_params"]
            assert cluster_params.platform is not None

            # Check platform was set correctly
            platform_obj = cluster_params.platform
            assert platform_obj.type == platform
            assert platform_obj.external is None

    @pytest.mark.asyncio
    async def test_update_cluster_platform_sets_umn_when_required(
        self, client: InventoryClient
    ) -> None:
        cluster_id = "test-cluster-id"
        cluster = create_test_cluster(cluster_id=cluster_id)
        with patch.object(client, "_installer_api") as mock_installer_api:
            mock_api = Mock()
            mock_api.v2_update_cluster.return_value = cluster
            mock_installer_api.return_value = mock_api
            result = await client.update_cluster(cluster_id, platform="none")
            assert result == cluster
            _args, kwargs = mock_api.v2_update_cluster.call_args
            params = kwargs["cluster_update_params"]
            assert params.platform.type == "none"

    @pytest.mark.asyncio
    async def test_update_host_success(self, client: InventoryClient) -> None:
        """Test successful host update."""
        host_id = "test-host-id"
        infra_env_id = "test-infra-env-id"
        host_role = "master"
        host = create_test_host(host_id=host_id, role=host_role)

        with patch.object(client, "_installer_api") as mock_installer_api:
            mock_api = Mock()
            mock_api.v2_update_host.return_value = host
            mock_installer_api.return_value = mock_api

            result = await client.update_host(
                host_id, infra_env_id, host_role=host_role
            )

            assert result == host
            mock_api.v2_update_host.assert_called_once()

            # Verify the call arguments
            args, _kwargs = mock_api.v2_update_host.call_args
            assert args[0] == infra_env_id
            assert args[1] == host_id

            # Verify the host update params contain the correct role
            host_update_params = args[2]  # Third positional argument
            assert host_update_params.host_role == host_role

    @pytest.mark.asyncio
    async def test_get_presigned_for_cluster_credentials_api_exception(
        self, client: InventoryClient
    ) -> None:
        """Test presigned URL retrieval API exception handling."""
        cluster_id = "test-cluster-id"
        file_name = "kubeconfig"

        with patch.object(client, "_installer_api") as mock_installer_api:
            mock_api = Mock()
            mock_api.v2_get_presigned_for_cluster_credentials.side_effect = (
                ApiException(status=404, reason="Not Found")
            )
            mock_installer_api.return_value = mock_api

            with pytest.raises(AssistedServiceAPIError) as exc_info:
                await client.get_presigned_for_cluster_credentials(
                    cluster_id, file_name
                )

            assert "API error: Status 404" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_get_presigned_for_cluster_credentials_unexpected_exception(
        self, client: InventoryClient
    ) -> None:
        """Test presigned URL retrieval unexpected exception handling."""
        cluster_id = "test-cluster-id"
        file_name = "kubeconfig"

        with patch.object(client, "_installer_api") as mock_installer_api:
            mock_api = Mock()
            mock_api.v2_get_presigned_for_cluster_credentials.side_effect = ValueError(
                "Unexpected error"
            )
            mock_installer_api.return_value = mock_api

            with pytest.raises(AssistedServiceAPIError) as exc_info:
                await client.get_presigned_for_cluster_credentials(
                    cluster_id, file_name
                )

            assert "An internal error occurred" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_get_presigned_for_cluster_credentials_different_file_types(
        self, client: InventoryClient
    ) -> None:
        """Test presigned URL retrieval for different credential file types."""
        cluster_id = "test-cluster-id"
        file_types = ["kubeconfig", "kubeconfig-noingress", "kubeadmin-password"]

        for file_name in file_types:
            presigned_url = create_test_presigned_url(
                url=f"https://example.com/presigned-url/{file_name}",
            )

            with patch.object(client, "_installer_api") as mock_installer_api:
                mock_api = Mock()
                mock_api.v2_get_presigned_for_cluster_credentials.return_value = (
                    presigned_url
                )
                mock_installer_api.return_value = mock_api

                result = await client.get_presigned_for_cluster_credentials(
                    cluster_id, file_name
                )

                assert result == presigned_url
                mock_api.v2_get_presigned_for_cluster_credentials.assert_called_once_with(
                    cluster_id=cluster_id, file_name=file_name
                )

    @pytest.mark.asyncio
    async def test_get_presigned_for_cluster_credentials_url_only(
        self, client: InventoryClient
    ) -> None:
        """Test presigned URL retrieval when only URL is returned (no expires_at)."""
        cluster_id = "test-cluster-id"
        file_name = "kubeconfig"
        presigned_url = create_test_presigned_url(expires_at=None)

        with patch.object(client, "_installer_api") as mock_installer_api:
            mock_api = Mock()
            mock_api.v2_get_presigned_for_cluster_credentials.return_value = (
                presigned_url
            )
            mock_installer_api.return_value = mock_api

            result = await client.get_presigned_for_cluster_credentials(
                cluster_id, file_name
            )

            assert result == presigned_url
            mock_api.v2_get_presigned_for_cluster_credentials.assert_called_once_with(
                cluster_id=cluster_id, file_name=file_name
            )

    @pytest.mark.asyncio
    async def test_get_infra_env_download_url_success(
        self, client: InventoryClient
    ) -> None:
        """Test successful presigned URL retrieval for infra env download."""
        infra_env_id = "test-infraenv-id"
        presigned_url = create_test_presigned_url(
            url="https://example.com/infra-env-download",
            expires_at="2023-12-31T23:59:59Z",
        )

        with patch.object(client, "_installer_api") as mock_installer_api:
            mock_api = Mock()
            mock_api.get_infra_env_download_url.return_value = presigned_url
            mock_installer_api.return_value = mock_api

            result = await client.get_infra_env_download_url(infra_env_id)

            assert result == presigned_url
            mock_api.get_infra_env_download_url.assert_called_once_with(
                infra_env_id=infra_env_id
            )

    @pytest.mark.asyncio
    async def test_get_infra_env_download_url_api_exception(
        self, client: InventoryClient
    ) -> None:
        """Test infra env download URL retrieval API exception handling."""
        infra_env_id = "test-infraenv-id"

        with patch.object(client, "_installer_api") as mock_installer_api:
            mock_api = Mock()
            mock_api.get_infra_env_download_url.side_effect = ApiException(
                status=404, reason="Not Found"
            )
            mock_installer_api.return_value = mock_api

            with pytest.raises(AssistedServiceAPIError) as exc_info:
                await client.get_infra_env_download_url(infra_env_id)

            assert "API error: Status 404" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_get_infra_env_download_url_unexpected_exception(
        self, client: InventoryClient
    ) -> None:
        """Test infra env download URL retrieval unexpected exception handling."""
        infra_env_id = "test-infraenv-id"

        with patch.object(client, "_installer_api") as mock_installer_api:
            mock_api = Mock()
            mock_api.get_infra_env_download_url.side_effect = ValueError(
                "Unexpected error"
            )
            mock_installer_api.return_value = mock_api

            with pytest.raises(AssistedServiceAPIError) as exc_info:
                await client.get_infra_env_download_url(infra_env_id)

            assert "An internal error occurred" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_get_infra_env_download_url_no_expiration(
        self, client: InventoryClient
    ) -> None:
        """Test infra env download URL retrieval when no expiration is returned."""
        infra_env_id = "test-infraenv-id"
        presigned_url = create_test_presigned_url(
            url="https://example.com/infra-env-download", expires_at=None
        )

        with patch.object(client, "_installer_api") as mock_installer_api:
            mock_api = Mock()
            mock_api.get_infra_env_download_url.return_value = presigned_url
            mock_installer_api.return_value = mock_api

            result = await client.get_infra_env_download_url(infra_env_id)

            assert result == presigned_url
            mock_api.get_infra_env_download_url.assert_called_once_with(
                infra_env_id=infra_env_id
            )
