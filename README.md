# MCP server for Red Hat OpenShift assisted installer

MCP server for interacting with the OpenShift assisted installer API.

Diagnose cluster failures and find out how to fix them.

## Try it out:

1. Clone the repo:
```
    git clone git@github.com:openshift-assisted/assisted-service-mcp.git
    cd assisted-service-mcp
```

2. Get your OpenShift API token from https://cloud.redhat.com/openshift/token

3. The server is started and configured differently depending on what transport you want to use

      #### For Streamable HTTP (recommended and the default):

      Start the server in a terminal:

      `OFFLINE_TOKEN='<your token>' uv run python -m assisted_service_mcp.src.main`

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

      #### For SSE (legacy HTTP+SSE):

      Start the server in a terminal:

      `TRANSPORT=sse OFFLINE_TOKEN='<your token>' uv run python -m assisted_service_mcp.src.main`

      The `TRANSPORT` environment variable defaults to `streamable-http`. Set `TRANSPORT=sse` to use the legacy HTTP+SSE transport.

      Configure the server in the client:

      ```json
        "assisted-sse": {
          "transport": "sse",
          "url": "http://localhost:8000/sse"
          }
      ```

      #### Providing the Offline Token via Request Header

      If both are configured, a non-empty `OCM-Offline-Token` HTTP request header takes precedence over the `OFFLINE_TOKEN` environment variable. If the header is absent or empty, the server uses the `OFFLINE_TOKEN` environment variable.

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


4. Ask about your clusters:

      In an MCP-compatible AI client connected to this server, ask for example: “List my Assisted Installer clusters.” After getting a cluster ID, ask: “Show me details about cluster `<cluster-id-from-list_clusters>`.” 

      ![Copilot checking Assisted Installer cluster status with cluster_info](images/cluster-prompt-example.png)

## Available Tools

The MCP server provides the following tools for interacting with the OpenShift Assisted Installer:

### Cluster Management

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

### Events and Monitoring

* **cluster_events** - Get the events related to a cluster with the given ID
  * `cluster_id`: Cluster ID (string, required)

* **host_events** - Get the events related to a specific host within a cluster
  * `cluster_id`: Cluster ID (string, required)
  * `host_id`: Host ID (string, required)

* **cluster_logs_download_url** - Get a presigned URL to download the cluster log bundle. Returns a JSON object with a `url` field, or an error.
  * `cluster_id`: Cluster ID (string, required)

* **analyze_cluster_logs** - Analyze available Assisted Installer logs for a cluster and summarize detected issues. Set the `ENABLE_TROUBLESHOOTING_TOOLS` environment variable to `1` in the MCP server environment to enable this tool; it defaults to `0`. For a hosted server, ask the service operator to enable it. Clients cannot enable it themselves.
  * `cluster_id`: Cluster ID (string, required)

### ISO Download URL

* **cluster_iso_download_url** - Get ISO download URL(s) for a cluster. Returns a JSON array of objects with a `url` and optional `expires_at` timestamp for each ISO. If no ISO URLs are found, returns a message.
  * `cluster_id`: Cluster ID (string, required)

### Host Management

* **set_host_role** - Assign a role to a discovered host. Valid roles are `auto-assign`, `master`, and `worker`.
  * `host_id`: Host ID (string, required)
  * `cluster_id`: Cluster ID containing the host (string, required)
  * `role`: Host role (`auto-assign`, `master`, or `worker`; string, required)

### Network Configuration

* **set_cluster_vips** - Set the API and ingress virtual IP addresses (VIPs) for the cluster
  * `cluster_id`: Cluster ID (string, required)
  * `api_vip`: API virtual IP address (string, required)
  * `ingress_vip`: Ingress virtual IP address (string, required)

* **validate_nmstate_yaml** - Validate NMState YAML syntax before applying it to hosts.
  * `nmstate_yaml`: NMState YAML document (string, required)

* **generate_nmstate_yaml** - Generate NMState YAML from structured network parameters. `ethernet_ifaces` must contain at least one interface.
  * `params`: Network configuration object (required). Supports `dns`, `routes`, `bond_ifaces`, `vlan_ifaces`, and `ethernet_ifaces`.

* **alter_static_network_config_nmstate_for_host** - Add, replace, or remove a host static network configuration for a cluster.
  * `cluster_id`: Cluster ID (string, required)
  * `index`: Configuration position to replace or remove, or `null` to append (integer or null, required)
  * `new_nmstate_yaml`: Validated NMState YAML to add or replace a configuration, or `null` to remove one (string or null, required)

* **list_static_network_config** - List the cluster static network configurations as a JSON array. Requires the cluster to have exactly one InfraEnv.
  * `cluster_id`: Cluster ID (string, required)

### SSH Key Management

* **set_cluster_ssh_key** - Set or update the SSH public key for a cluster. This enables SSH access to cluster nodes during and after installation. Only ISOs downloaded after the update include the new key; hosts that have already booted must boot from a new ISO to receive it.
  * `cluster_id`: Cluster ID (string, required)
  * `ssh_public_key`: SSH public key in OpenSSH format (string, required)

### OpenShift Versions and Operators

* **list_versions** - Lists the available OpenShift versions for installation with the assisted installer. Takes no parameters.

* **list_operator_bundles** - Lists operator bundles available to add to a cluster before installation. Takes no parameters.

* **add_operator_bundle_to_cluster** - Request an operator bundle to be installed with the cluster. Add the bundle before starting cluster installation.
  * `cluster_id`: Cluster ID (string, required)
  * `bundle_name`: Operator bundle name (string, required)

### Tool Effects

| Category | Meaning | Tools |
|---|---|---|
| State-changing | Creates or updates cluster or host settings; not marked destructive. | `create_cluster`, `add_operator_bundle_to_cluster`, `set_host_role` |
| Potentially destructive | May change installation, cluster, or network configuration. | `set_cluster_vips`, `set_cluster_platform`, `install_cluster`, `set_cluster_ssh_key`, `alter_static_network_config_nmstate_for_host` |

MCP annotations are advisory, not access controls. Other tools have no explicit effect annotations.

### Usage Examples

These are example requests to enter in an MCP-compatible AI client configured to connect to this server; the agent uses each request to call the corresponding tool.

* **List all clusters**: "Show me all my clusters"
* **Get cluster details**: "Give me detailed information about cluster abc123"
* **Create a cluster**: "Create a multi-node cluster named 'my-cluster' with OpenShift 4.14, base domain 'example.com', and single_node set to false."
* **Check cluster events**: "What events happened on cluster abc123?"
* **Install a cluster**: "Start the installation for cluster abc123"
* **Get cluster credentials**: "Get the kubeconfig download link for cluster abc123"
* **Update SSH key**: "Set the SSH key for cluster abc123 so I can access the nodes"

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
