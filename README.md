# MCP server for Red Hat OpenShift assisted installer

MCP server for interacting with the OpenShift assisted installer API.

Diagnose cluster failures and find out how to fix them.

## Getting Started

1. Clone the repository:

   ```bash
   git clone git@github.com:openshift-assisted/assisted-service-mcp.git
   cd assisted-service-mcp
   ```

2. Get a Red Hat offline token for the MCP server from <https://cloud.redhat.com/openshift/token>. Alternatively, send a valid Red Hat API access token in an `Authorization: Bearer <token>` request header (see step 4).

3. Start and configure the server for the transport you want to use. The JSON blocks below are illustrative server-entry fragments; configuration syntax varies by MCP client, so adapt the relevant entry to your client configuration.

    **For Streamable HTTP (recommended and the default)**

    Start the server in a terminal:

    ```bash
    OFFLINE_TOKEN='<your token>' uv run python -m assisted_service_mcp.src.main
    ```

    Configure the server in the client:

    ```json
    "assisted-http": {
      "transport": "streamable-http",
      "url": "http://localhost:8000/mcp"
    }
    ```

    Streamable HTTP is the default transport. It was introduced in MCP protocol version `2025-03-26` to replace the legacy HTTP+SSE transport from version `2024-11-05`.

    See the MCP specification's [HTTP authorization guidance](https://modelcontextprotocol.io/specification/2026-07-28/basic).

    It is also the default here because the [Red Hat Connectivity Link MCP Gateway](https://docs.redhat.com/en/documentation/red_hat_connectivity_link/1.4/html/install_the_mcp_gateway/mcp-gateway-install) supports it and routes MCP traffic to `/mcp`. See the [MCP transport specification](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http) for details.

    **For SSE (legacy HTTP+SSE)**

    Start the server in a terminal:

    ```bash
    TRANSPORT=sse OFFLINE_TOKEN='<your token>' uv run python -m assisted_service_mcp.src.main
    ```

    The `TRANSPORT` environment variable defaults to `streamable-http`. Set `TRANSPORT=sse` to use the legacy HTTP+SSE transport.

    Configure the server in the client:

    ```json
    "assisted-sse": {
      "transport": "sse",
      "url": "http://localhost:8000/sse"
    }
    ```

4. Providing the Offline Token via Request Header

    If both are configured, a non-empty `OCM-Offline-Token` HTTP request header takes precedence over the `OFFLINE_TOKEN` environment variable. If the header is absent or empty, the server uses the `OFFLINE_TOKEN` environment variable. A valid `Authorization: Bearer <token>` request header takes precedence over both offline-token sources and is used directly as the API access token.

    To provide the token in a request header, add `OCM-Offline-Token` to your MCP client configuration:

    ```json
    "assisted-http": {
      "transport": "streamable-http",
      "url": "http://localhost:8000/mcp",
      "headers": {
        "OCM-Offline-Token": "<your token>"
      }
    }
    ```

5. Ask about your clusters

    In an MCP-compatible AI client connected to this server, ask for example: “List my Assisted Installer clusters.” After getting a cluster ID, ask: “Show me details about cluster `<cluster-id-from-list_clusters>`.”

    ![Copilot checking Assisted Installer cluster status with cluster_info](images/cluster-prompt-example.png)

## Available MCP Tools

The MCP server provides the following tools for interacting with the OpenShift Assisted Installer:

There are 20 tools by default. Enabling the optional `analyze_cluster_logs` tool brings the total to 21.

### &emsp;&nbsp;&nbsp;Cluster Management

* **list_clusters** - Lists all current user assisted installer clusters. Returns minimal cluster information.

* **cluster_info** - Get detailed information about the assisted installer cluster with the given ID
  * `cluster_id`: Cluster ID (string, required)

* **create_cluster** - Create a new assisted installer cluster and InfraEnv. Set single_node to true only for single-node clusters or when high availability is not needed. Returns the cluster UUID as text; the InfraEnv ID is not returned.
  * `name`: Cluster name (string, required)
  * `version`: OpenShift version (string, required)
  * `base_domain`: Base domain for the cluster (string, required)
  * `single_node`: Whether to create a single node cluster (boolean, required)
  * `ssh_public_key`: SSH public key for accessing cluster nodes (string, optional)
  * `cpu_architecture`: CPU architecture (`x86_64`, `aarch64`, `arm64`, `ppc64le`, or `s390x`; optional, defaults to `x86_64`)
  * `platform`: Infrastructure platform (`baremetal`, `vsphere`, `oci`, `nutanix`, or `none`; optional, defaults to `baremetal` for multi-node clusters and `none` for single-node clusters)

* **install_cluster** - Trigger installation for the assisted installer cluster with the given ID
  * `cluster_id`: Cluster ID (string, required)

* **cluster_credentials_download_url** - Get a time-limited download URL for cluster credentials after installation completes. Returns JSON with a `url` and optional `expires_at` timestamp.
  * `cluster_id`: Cluster ID (string, required)
  * `file_name`: Credential file (`kubeconfig`, `kubeconfig-noingress`, or `kubeadmin-password`; string, required)

* **set_cluster_platform** - Set or update the infrastructure platform for an existing cluster. Single-node clusters require `none`; changing the platform may require updating network settings.
  * `cluster_id`: Cluster ID (string, required)
  * `platform`: Platform (`baremetal`, `vsphere`, `oci`, `nutanix`, or `none`; string, required)

### &emsp;&nbsp;&nbsp;Events and Monitoring

* **cluster_events** - Get the events related to a cluster with the given ID
  * `cluster_id`: Cluster ID (string, required)

* **host_events** - Get the events related to a specific host within a cluster
  * `cluster_id`: Cluster ID (string, required)
  * `host_id`: Host ID (string, required)

* **cluster_logs_download_url** - Get a presigned URL to download the cluster log bundle. Returns a JSON object with a `url` field, or an error.
  * `cluster_id`: Cluster ID (string, required)

* **analyze_cluster_logs** - Analyze available Assisted Installer logs for a cluster and summarize detected issues. Set the `ENABLE_TROUBLESHOOTING_TOOLS` environment variable to `1` in the MCP server environment to enable this tool; it defaults to `0`. For a hosted server, ask the service operator to enable it. Clients cannot enable it themselves.
  * `cluster_id`: Cluster ID (string, required)

### &emsp;&nbsp;&nbsp;ISO Download URL(s)

* **cluster_iso_download_url** - Get ISO download URL(s) for a cluster. Returns a JSON array of objects with a `url` and optional `expires_at` timestamp for each ISO. If no ISO URLs are found, returns a message.
  * `cluster_id`: Cluster ID (string, required)

### &emsp;&nbsp;&nbsp;Host Management

* **set_host_role** - Assign a role to a discovered host. Valid roles are `auto-assign`, `master`, and `worker`. If the cluster has multiple InfraEnvs, the tool uses the first one; if the target host belongs to another InfraEnv, the role update can fail with a 404 Not Found error.
  * `host_id`: Host ID (string, required)
  * `cluster_id`: Cluster ID containing the host (string, required)
  * `role`: Host role (`auto-assign`, `master`, or `worker`; string, required)

### &emsp;&nbsp;&nbsp;Network Configuration

* **set_cluster_vips** - Set the API and ingress virtual IP addresses (VIPs) for the cluster
  * `cluster_id`: Cluster ID (string, required)
  * `api_vip`: API virtual IP address (string, required)
  * `ingress_vip`: Ingress virtual IP address (string, required)

* **validate_nmstate_yaml** - Validate NMState YAML syntax before applying it to hosts.
  * `nmstate_yaml`: NMState YAML document (string, required)

* **generate_nmstate_yaml** - Generate NMState YAML from structured network parameters. `ethernet_ifaces` must contain at least one interface.
  * `params`: Network configuration object (required). Supports `dns`, `routes`, `bond_ifaces`, `vlan_ifaces`, and `ethernet_ifaces`.

* **alter_static_network_config_nmstate_for_host** - Add, replace, or remove a host static network configuration for a cluster. The tool changes only the first InfraEnv returned for the cluster; manage other InfraEnvs separately. `index` selects a configuration within that InfraEnv, not an InfraEnv.
  * `cluster_id`: Cluster ID (string, required)
  * `index`: Position in the first InfraEnv’s static network configuration list to replace or remove, or `null` to append (integer or null, required)
  * `new_nmstate_yaml`: Validated NMState YAML to add or replace a configuration, or `null` to remove one (string or null, required)

* **list_static_network_config** - Returns the cluster static network configurations as a JSON array encoded string. Requires the cluster to have exactly one InfraEnv.
  * `cluster_id`: Cluster ID (string, required)

### &emsp;&nbsp;&nbsp;SSH Key Management

* **set_cluster_ssh_key** - Set or update the SSH public key for a cluster. This enables SSH access to cluster nodes during and after installation. Only ISOs downloaded after the update include the new key; hosts that have already booted must boot from a new ISO to receive it. If the cluster has multiple InfraEnvs, the tool updates only the first one; ISOs from other InfraEnvs may not include the new key.
  * `cluster_id`: Cluster ID (string, required)
  * `ssh_public_key`: SSH public key in OpenSSH format (string, required)

### &emsp;&nbsp;&nbsp;OpenShift Versions and Operators

* **list_versions** - Lists the available OpenShift versions for installation with the assisted installer. Takes no parameters.

* **list_operator_bundles** - Lists operator bundles available to add to a cluster before installation. Takes no parameters.

* **add_operator_bundle_to_cluster** - Update the cluster's operator configuration so the selected operator bundle will be installed with the cluster. This may remove previously configured operators that are not included in the selected bundle. Use before starting cluster installation.

  * `cluster_id`: Cluster ID (string, required)
  * `bundle_name`: Operator bundle name (string, required)

## Example Prompts for MCP Clients

These are example requests to enter in an MCP-compatible AI client configured to connect to this server; the agent uses each request to call the corresponding tool.

* **List all clusters**: "Show me all my clusters"
* **Get cluster details**: "Give me detailed information about cluster abc123"
* **Create a cluster**: "Create a multi-node cluster named my-cluster using a currently available OpenShift version and base domain example.com."
* **Check cluster events**: "What events happened on cluster abc123?"
* **Install a cluster**: "Start the installation for cluster abc123"
* **Get cluster credentials**: "After cluster abc123 is installed, get the kubeconfig download link."
* **Update SSH key**: "Set the SSH public key for cluster abc123 to `<ssh-public-key>` so I can access the nodes." Hosts that have already booted must boot from a new ISO to receive the updated key.

## MCP Tool Effect Annotations

**Read-only**  
Retrieves or validates information without changing cluster state. All tools outside the two annotated groups are read-only and have no effect annotations.

**State-changing**  
Changes cluster state without being marked destructive.

**Destructive**  
May alter configuration or start installation, with effects that can be hard to reverse.

The annotations are advisory and do not enforce access control.

<dl>
  <dd>
    <table>
      <thead>
        <tr>
          <th>Category</th>
          <th>Annotation values</th>
          <th>Meaning</th>
          <th>Tools</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td>State-changing</td>
          <td><code>readOnlyHint=False</code>, <code>destructiveHint=False</code></td>
          <td>Changes state but is not marked destructive.</td>
          <td><code>create_cluster</code></td>
        </tr>
        <tr>
          <td>Destructive</td>
          <td><code>readOnlyHint=False</code>, <code>destructiveHint=True</code></td>
          <td>May alter cluster, host, operator, or network configuration, or start installation; effects may be hard to reverse.</td>
          <td><code>set_cluster_vips</code>, <code>set_cluster_platform</code>, <code>install_cluster</code>, <code>set_cluster_ssh_key</code>, <code>alter_static_network_config_nmstate_for_host</code>, <code>add_operator_bundle_to_cluster</code>, <code>set_host_role</code></td>
        </tr>
      </tbody>
    </table>
  </dd>
</dl>

## Prometheus Metrics

The server exposes Prometheus metrics for tool usage and performance at `/metrics`. When running locally with the default `MCP_PORT=8000`, access them at `http://localhost:8000/metrics`. For other deployments, use the server's reachable address and configured port.

### Available Metrics

* **assisted_service_mcp_tool_request_count** - Number of tool requests.
* **assisted_service_mcp_tool_request_duration_sum** - Total time to run the tool, in seconds.
* **assisted_service_mcp_tool_request_duration_count** - Total number of tool requests measured.
* **assisted_service_mcp_tool_request_duration_bucket** - Cumulative number of tool requests up to each latency bucket.

### Metric Labels

All tool request metrics include the following label:

**tool** - The name of the MCP tool whose request is measured, for example `cluster_info` or `list_clusters`. This lets you distinguish request counts and durations for each tool.
