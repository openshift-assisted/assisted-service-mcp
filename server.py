from mcp.server.fastmcp import FastMCP
import asyncio
import base64
import hashlib
import httpx
import json
import os
import starlette.requests
import starlette.responses
import urllib.parse
import webbrowser

from service_client import InventoryClient

mcp = FastMCP("AssistedService", host="0.0.0.0")

class AuthCodeFlowHelper:
    """
    Simplifies use of the OAuth authorization code flow.
    """

    # These are the settings to use the 'ocm-cli' client. We should probably consider creating a
    # client specifically for our use.
    CLIENT_ID = "ocm-cli"
    AUTH_URL = "https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/auth"
    TOKEN_URL = "https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/token"
    CALLBACK_TIMEOUT = 300

    def __init__(self):
        # Create the async event that will be used to coordinate with the callback:
        self._callback_event = asyncio.Event()
        self._callback_code: str | None = None

        # We will save the tokens in order to avoid running the flow for each request:
        self._refresh_token: str | None = None
        self._access_token: str | None = None

    async def run(self) -> tuple[str, str]:
        """
        Runs the OAuth authorization code flow.

        This method opens the URL of the authorization server provider in a browser, so that the user
        can provide the credentials. If credentials are correct, the identity provider will send a
        request to the '/oauth/callback' endpoint, containing the authorization code, which will then
        be exchanged for the access and refresh tokens.

        Returns:
            (str, str): A tuple containing the refresh and access tokens, in that order.

        Raises:
            RuntimeError: If something fails during the process.
        """
        # Don't run the flow if we already have the tokens:
        if self._refresh_token is not None and self._access_token is not None:
            return (self._refresh_token, self._access_token)

        # Generate a random challenge:
        challenge_bytes = os.urandom(32)
        challenge_verifier = base64.urlsafe_b64encode(challenge_bytes).rstrip(b'=').decode('utf-8')
        challenge_hash = hashlib.sha256(challenge_verifier.encode('utf-8')).digest()
        challenge_text = base64.urlsafe_b64encode(challenge_hash).rstrip(b'=').decode('utf-8')

        # Build the ahtorization URL and open it in the browser:
        callback_url = f"http://127.0.0.1:8000/oauth/callback"
        auth_query = urllib.parse.urlencode({
            "response_type": "code",
            "client_id": self.CLIENT_ID,
            "redirect_uri": callback_url,
            "scope": "openid",
            "code_challenge": challenge_text,
            "code_challenge_method": "S256",
        })
        auth_url = f"{self.AUTH_URL}?{auth_query}"
        webbrowser.open_new_tab(auth_url)

        # Wait till the code has been received:
        try:
            await asyncio.wait_for(self._callback_event.wait(), timeout=self.CALLBACK_TIMEOUT)
        except TimeoutError:
            raise RuntimeError(f"Failed to get the auth code after waiting for {self.CALLBACK_TIMEOUT} seconds")

        # Exchange the code for the tokens:
        auth_response = httpx.post(
            self.TOKEN_URL,
            data={
                "grant_type": "authorization_code",
                "code": self._callback_code,
                "client_id": self.CLIENT_ID,
                "redirect_uri": callback_url,
                "code_verifier": challenge_verifier,
            },
        )
        auth_response.raise_for_status()
        auth_body = auth_response.json()
        self._refresh_token = auth_body.get("refresh_token")
        if self._refresh_token is None:
            raise RuntimeError("Response doesn't contain the refresh token")
        self._access_token = auth_body.get("access_token")
        if self._access_token is None:
            raise RuntimeError("Response doesn't contain the access token")
        return (self._refresh_token, self._access_token)

    async def callback(self, request: starlette.requests.Request) -> starlette.responses.Response:
        """
        Processes the callback sent by the authorization server.

        Args:
            request (starlette.requests.Request): The HTTP request.

        Returns:
            response (starlette.responses.Response): The HTTP response.
        """
        self._callback_code = request.query_params["code"]
        self._callback_event.set()
        return starlette.responses.HTMLResponse(
            status_code=200,
            content="Received the authorization code, you can return to your MCP client now.",
        )

# Single instance of the authorization code flow helper. It will be created only when the flow
# is enabled.
auth_code_flow_helper: AuthCodeFlowHelper | None = None

@mcp.custom_route(
    path="/oauth/callback",
    methods=[
        "GET",
    ],
)
async def oauth_callback(request: starlette.requests.Request) -> starlette.responses.Response:
    if auth_code_flow_helper is None:
        return starlette.responses.Response(status_code=404)
    return await auth_code_flow_helper.callback(request)

async def get_offline_token() -> str:
    """Retrieve the offline token from environment variables or request headers.

    This function attempts to get the Red Hat OpenShift Cluster Manager (OCM) refresh token
    first using the authorization code flow, if it is enabled, or trying to get it from
    the OFFLINE_TOKEN environment variable, and finally from the OCM-Offline-Token request
    header. The token is required for authenticating with the Red Hat assisted installer service.

    Returns:
        str: The offline token string used for authentication.

    Raises:
        RuntimeError: If no offline token is found in either environment variables
            or request headers.
    """
    if auth_code_flow_helper is not None:
        (refresh_token, _) = await auth_code_flow_helper.run()
        return refresh_token

    token = os.environ.get("OFFLINE_TOKEN")
    if token:
        return token

    token = mcp.get_context().request_context.request.headers.get("OCM-Offline-Token")
    if token:
        return token

    raise RuntimeError("No offline token found in environment or request headers")

@mcp.tool()
async def cluster_info(cluster_id: str) -> str:
    """Get comprehensive information about a specific assisted installer cluster.

    Retrieves detailed cluster information including configuration, status, hosts,
    network settings, and installation progress for the specified cluster ID.

    Args:
        cluster_id (str): The unique identifier of the cluster to retrieve information for.
            This is typically a UUID string.

    Returns:
        str: A formatted string containing detailed cluster information including:
            - Cluster name, ID, and OpenShift version
            - Installation status and progress
            - Network configuration (VIPs, subnets)
            - Host information and roles
    """
    token = await get_offline_token()
    return InventoryClient(token).get_cluster(cluster_id=cluster_id).to_str()

@mcp.tool()
async def list_clusters() -> str:
    """List all assisted installer clusters for the current user.

    Retrieves a summary of all clusters associated with the current user's account.
    This provides basic information about each cluster without detailed configuration.
    Use cluster_info() to get comprehensive details about a specific cluster.

    Returns:
        str: A JSON-formatted string containing an array of cluster objects.
            Each cluster object includes:
            - name (str): The cluster name
            - id (str): The unique cluster identifier
            - openshift_version (str): The OpenShift version being installed
            - status (str): Current cluster status (e.g., 'ready', 'installing', 'error')
    """
    token = await get_offline_token()
    clusters = InventoryClient(token).list_clusters()
    resp = [{"name": cluster["name"], "id": cluster["id"], "openshift_version": cluster["openshift_version"], "status": cluster["status"]} for cluster in clusters]
    return json.dumps(resp)

@mcp.tool()
async def cluster_events(cluster_id: str) -> str:
    """Get the events related to a cluster with the given cluster id.

    Retrieves chronological events related to cluster installation, configuration
    changes, and status updates. These events help track installation progress
    and diagnose issues.

    Args:
        cluster_id (str): The unique identifier of the cluster to get events for.

    Returns:
        str: A JSON-formatted string containing cluster events with timestamps,
            event types, and descriptive messages about cluster activities.
    """
    token = await get_offline_token()
    return InventoryClient(token).get_events(cluster_id=cluster_id)

@mcp.tool()
async def host_events(cluster_id: str, host_id: str) -> str:
    """Get events specific to a particular host within a cluster.

    Retrieves events related to a specific host's installation progress, hardware
    validation, role assignment, and any host-specific issues or status changes.

    Args:
        cluster_id (str): The unique identifier of the cluster containing the host.
        host_id (str): The unique identifier of the specific host to get events for.

    Returns:
        str: A JSON-formatted string containing host-specific events including
            hardware validation results, installation steps, and error messages.
    """
    token = await get_offline_token()
    return InventoryClient(token).get_events(cluster_id=cluster_id, host_id=host_id)

@mcp.tool()
async def infraenv_info(infraenv_id: str) -> str:
    """Get detailed information about an infrastructure environment (InfraEnv).

    An InfraEnv contains the configuration and resources needed to boot and discover
    hosts for cluster installation, including the discovery ISO image and network
    configuration.

    Args:
        infraenv_id (str): The unique identifier of the infrastructure environment.

    Returns:
        str: A formatted string containing comprehensive InfraEnv information including:
            - ISO download URL for host discovery
            - Network configuration and proxy settings
            - SSH public key for host access
            - Associated cluster information
            - Static network configuration if applicable
    """
    token = await get_offline_token()
    return InventoryClient(token).get_infra_env(infraenv_id).to_str()

@mcp.tool()
async def create_cluster(name: str, version: str, base_domain: str, single_node: bool) -> str:
    """Create a new OpenShift cluster and associated infrastructure environment.

    Creates both a cluster definition and an InfraEnv for host discovery. The cluster
    can be configured for high availability (multi-node) or single-node deployment.

    Args:
        name (str): The name for the new cluster. Must be unique within your account.
        version (str): The OpenShift version to install (e.g., "4.18.2", "4.17.1").
            Use list_versions() to see available versions.
        base_domain (str): The base DNS domain for the cluster (e.g., "example.com").
            The cluster will be accessible at api.{name}.{base_domain}.
        single_node (bool): Whether to create a single-node cluster. Set to True for
            edge deployments or resource-constrained environments. Set to False for
            production high-availability clusters with multiple control plane nodes.

    Returns:
        str: A JSON string containing the created cluster and InfraEnv IDs:
            - cluster_id (str): The unique identifier of the created cluster
            - infraenv_id (str): The unique identifier of the created InfraEnv
    """
    token = await get_offline_token()
    client = InventoryClient(token)
    cluster = client.create_cluster(name, version, single_node, base_dns_domain=base_domain)
    infraenv = client.create_infra_env(name, cluster_id=cluster.id, openshift_version=cluster.openshift_version)
    return json.dumps({'cluster_id': cluster.id, 'infraenv_id': infraenv.id})

@mcp.tool()
async def set_cluster_vips(cluster_id: str, api_vip: str, ingress_vip: str) -> str:
    """Configure the virtual IP addresses (VIPs) for cluster API and ingress traffic.

    Sets the API VIP (for cluster management) and Ingress VIP (for application traffic)
    for the specified cluster. These VIPs must be available IP addresses within the
    cluster's network subnet.

    Args:
        cluster_id (str): The unique identifier of the cluster to configure.
        api_vip (str): The IP address for the cluster API endpoint. This is where
            kubectl and other management tools will connect.
        ingress_vip (str): The IP address for ingress traffic to applications
            running in the cluster.

    Returns:
        str: A formatted string containing the updated cluster configuration
            showing the newly set VIP addresses.
    """
    token = await get_offline_token()
    return InventoryClient(token).update_cluster(cluster_id, api_vip=api_vip, ingress_vip=ingress_vip).to_str()

@mcp.tool()
async def install_cluster(cluster_id: str) -> str:
    """Trigger the installation process for a prepared cluster.

    Initiates the OpenShift installation on all discovered and validated hosts.
    The cluster must have all prerequisites met including sufficient hosts,
    network configuration, and any required validations.

    Args:
        cluster_id (str): The unique identifier of the cluster to install.

    Returns:
        str: A formatted string containing the cluster status after installation
            has been triggered, including installation progress information.

    Note:
        Before calling this function, ensure:
        - All required hosts are discovered and ready
        - Network configuration is complete (VIPs set if required)
        - All cluster validations pass
    """
    token = await get_offline_token()
    return InventoryClient(token).install_cluster(cluster_id).to_str()

@mcp.tool()
async def list_versions() -> str:
    """List all available OpenShift versions for installation.

    Retrieves the complete list of OpenShift versions that can be installed
    using the assisted installer service, including release versions and
    pre-release candidates.

    Returns:
        str: A JSON string containing available OpenShift versions with metadata
            including version numbers, release dates, and support status.
    """
    token = await get_offline_token()
    return json.dumps(InventoryClient(token).get_openshift_versions(True))

@mcp.tool()
async def list_operator_bundles() -> str:
    """List available operator bundles for cluster installation.

    Retrieves operator bundles that can be optionally installed during cluster
    deployment. These include Red Hat and certified partner operators for
    various functionalities like storage, networking, and monitoring.

    Returns:
        str: A JSON string containing available operator bundles with metadata
            including bundle names, descriptions, and operator details.
    """
    token = await get_offline_token()
    return json.dumps(InventoryClient(token).get_operator_bundles())

@mcp.tool()
async def add_operator_bundle_to_cluster(cluster_id: str, bundle_name: str) -> str:
    """Add an operator bundle to be installed with the cluster.

    Configures the specified operator bundle to be automatically installed
    during cluster deployment. The bundle must be from the list of available
    bundles returned by list_operator_bundles().

    Args:
        cluster_id (str): The unique identifier of the cluster to configure.
        bundle_name (str): The name of the operator bundle to add. Use
            list_operator_bundles() to see available bundle names.

    Returns:
        str: A formatted string containing the updated cluster configuration
            showing the newly added operator bundle.
    """
    token = await get_offline_token()
    return InventoryClient(token).add_operator_bundle_to_cluster(cluster_id, bundle_name).to_str()

@mcp.tool()
async def set_host_role(host_id: str, infraenv_id: str, role: str) -> str:
    """Assign a specific role to a discovered host in the cluster.

    Sets the role for a host that has been discovered through the InfraEnv boot process.
    The role determines the host's function in the OpenShift cluster.

    Args:
        host_id (str): The unique identifier of the host to configure.
        infraenv_id (str): The unique identifier of the InfraEnv containing the host.
        role (str): The role to assign to the host. Valid options are:
            - 'auto-assign': Let the installer automatically determine the role
            - 'master': Control plane node (API server, etcd, scheduler)
            - 'worker': Compute node for running application workloads

    Returns:
        str: A formatted string containing the updated host configuration
            showing the newly assigned role.
    """
    token = await get_offline_token()
    return InventoryClient(token).update_host(host_id, infraenv_id, host_role=role).to_str()

if __name__ == "__main__":
    # Create the authorization code flow helper if enabled:
    if os.getenv("USE_AUTHORIZATION_CODE_FLOW", "false").lower() == "true":
        auth_code_flow_helper = AuthCodeFlowHelper()

    # Run the server:
    mcp.run(transport="sse")
