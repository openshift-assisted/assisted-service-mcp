# Assisted Service MCP Server

MCP server for interacting with the OpenShift assisted installer API.

Diagnose cluster failures and find out how to fix them.

## Quick Start

### Option 1: Simple Token Setup

1. **Get your OpenShift API token** from https://cloud.redhat.com/openshift/token

2. **Clone and run**:
  ```bash
  git clone git@github.com:openshift-assisted/assisted-service-mcp.git
  cd assisted-service-mcp
  OFFLINE_TOKEN=<your token> uv run python -m assisted_service_mcp.src.main
  ```

3. **Configure your MCP client** (Cursor/Copilot):
  ```json
  {
    "assisted-service-mcp": {
      "transport": "streamable-http",
      "url": "http://127.0.0.1:8000/mcp"
    }
  }
  ```

### Option 2: OAuth Authentication (Advanced)

For automatic token management with Red Hat SSO:

1. **Clone the repo**:
  ```bash
  git clone git@github.com:openshift-assisted/assisted-service-mcp.git
  cd assisted-service-mcp
  ```

2. **Start the OAuth-enabled server**:
  ```bash
  ./start-oauth-server.sh
  ```

3. **Configure your MCP client** (Cursor/Copilot):
  ```json
  {
    "assisted-service-mcp": {
      "transport": "streamable-http",
      "url": "http://127.0.0.1:8000/mcp"
    }
  }
  ```

4. **Connect and authenticate**: When you connect from Cursor, a browser will open automatically for Red Hat SSO authentication.

**For detailed OAuth setup instructions, see [OAUTH_SETUP.md](doc/OAUTH_SETUP.md)**

### Option 3: OCM-Offline-Token Header
#### Note: this option is available only when OAuth is disabled 

1. **Get your OpenShift API token** from https://cloud.redhat.com/openshift/token

2. **Clone and run**:
  ```bash
  git clone git@github.com:openshift-assisted/assisted-service-mcp.git
  cd assisted-service-mcp
  uv run python -m assisted_service_mcp.src.main
  ```

```json
    "mcpServers": {
      "assisted": {
        "transport": "streamable-http",
        "url": "http://127.0.0.1:8000/mcp",
        "headers": {
          "OCM-Offline-Token": "<offline token>"
        }
      }
    }
```

## Advanced Transport Options

The recommended transport is streamable-http as shown in the examples above.
Other transport methods or detailed configuration:

**Configure the server** depending on your preferred transport:

#### STDIO Transport

In VSCode for example:
```json
   "mcp": {
        "servers": {
            "AssistedService": {
                "command": "uv",
                "args": [
                    "--directory",
                    "/path/to/assisted-service-mcp",
                    "run",
                    "mcp",
                    "run",
                    "/path/to/assisted-service-mcp/assisted_service_mcp/src/main.py"
                ],
                "env": {
                    "OFFLINE_TOKEN": "<your token>"
                }
            }
        }
    }
```

#### Server-Sent Events (SSE) Transport (Alternative)
#### Note: SSE is supported for backward compatibility, Streamable HTTP is the recommended transport
Start the server with SSE transport:

`OFFLINE_TOKEN=<your token> TRANSPORT=sse uv run python -m assisted_service_mcp.src.main`

Configure the client:

```json
{
  "assisted-sse": {
    "transport": "sse",
    "url": "http://127.0.0.1:8000/sse"
  }
}
```

## Authentication Methods

The server supports multiple authentication methods with automatic priority handling:

1. **Authorization Header** - `Bearer <token>` in request headers
2. **OAuth Flow** (when `OAUTH_ENABLED=true`) - Automatic browser-based authentication
3. **Environment Variable** - `OFFLINE_TOKEN` environment variable
4. **OCM-Offline-Token Header** - `OCM-Offline-Token: <token>` in request headers 

### OAuth Benefits (Advanced Users)

**No Manual Token Management** - Tokens are obtained and cached automatically
**Secure PKCE Flow** - Enhanced OAuth security with Proof Key for Code Exchange
**Automatic Token Refresh** - Expired tokens are refreshed transparently using refresh tokens
**Multi-Client Support** - Different MCP clients can authenticate independently

## Usage

Ask about your clusters:
![Example prompt asking about a cluster](images/cluster-prompt-example.png)

## Available Tools

The MCP server provides the following tools for interacting with the OpenShift Assisted Installer:

### Cluster Management

* **list_clusters** - Lists all current user assisted installer clusters. Returns minimal cluster information.

* **cluster_info** - Get detailed information about the assisted installer cluster with the given ID
  * `cluster_id`: Cluster ID (string, required)

* **create_cluster** - Create a new assisted installer cluster and infraenv. Set single_node to true only for single node clusters or when high availability is not needed. Returns cluster ID and infraenv ID as JSON.
  * `name`: Cluster name (string, required)
  * `version`: OpenShift version (string, required)
  * `base_domain`: Base domain for the cluster (string, required)
  * `single_node`: Whether to create a single node cluster (boolean, required)
  * `ssh_public_key`: SSH public key for accessing cluster nodes (string, optional)

* **install_cluster** - Trigger installation for the assisted installer cluster with the given ID
  * `cluster_id`: Cluster ID (string, required)

* **set_cluster_vips** - Set the API and ingress virtual IP addresses (VIPs) for the cluster
  * `cluster_id`: Cluster ID (string, required)
  * `api_vip`: API virtual IP address (string, required)
  * `ingress_vip`: Ingress virtual IP address (string, required)

### Events and Monitoring

* **cluster_events** - Get the events related to a cluster with the given ID
  * `cluster_id`: Cluster ID (string, required)

* **host_events** - Get the events related to a specific host within a cluster
  * `cluster_id`: Cluster ID (string, required)
  * `host_id`: Host ID (string, required)

### ISO Download URL

* **cluster_iso_download_url** - Get ISO download URL(s) for a cluster. A formatted string containing ISO download URLs and optional expiration times. Each ISO's information is formatted as:
  - URL: <download-url>
  - Expires at: <expiration-timestamp> (if available)
  Multiple ISOs are separated by blank lines.
  * `cluster_id`: Cluster ID (string, required)

### Host Management

* **set_host_role** - Update a host to a specific role. Role options are: 'auto-assign', 'master', 'arbiter', 'worker'
  * `host_id`: Host ID (string, required)
  * `infraenv_id`: Infrastructure environment ID (string, required)
  * `role`: Host role (string, required)

### SSH Key Management

* **set_cluster_ssh_key** - Set or update the SSH public key for a cluster. This allows SSH access to cluster nodes during and after installation.
  * `cluster_id`: Cluster ID (string, required)
  * `ssh_public_key`: SSH public key in OpenSSH format (string, required)

### OpenShift Versions and Operators

* **list_versions** - Lists the available OpenShift versions for installation with the assisted installer

* **list_operator_bundles** - Lists the operator bundles that can be optionally added to a cluster during installation

* **add_operator_bundle_to_cluster** - Request an operator bundle to be installed with the given cluster
  * `cluster_id`: Cluster ID (string, required)
  * `bundle_name`: Operator bundle name (string, required)

### Usage Examples

* **List all clusters**: "Show me all my clusters"
* **Get cluster details**: "Give me detailed information about cluster abc123"
* **Create a cluster**: "Create a new cluster named 'my-cluster' with OpenShift 4.14 and base domain 'example.com'"
* **Check cluster events**: "What events happened on cluster abc123?"
* **Install a cluster**: "Start the installation for cluster abc123"
* **Get cluster credentials**: "Get the kubeconfig download link for cluster abc123"
* **Update SSH key**: "Set the SSH key for cluster abc123 so I can access the nodes"

## Prometheus Metrics

The MCP server exposes Prometheus metrics to monitor tool usage and performance. The metrics are available at `http://localhost:8000/metrics` when the server is running.

### Available Metrics

* **assisted_service_mcp_tool_request_count** - Number of tool requests.
* **assisted_service_mcp_tool_request_duration_sum** - Total time to run the tool, in seconds.
* **assisted_service_mcp_tool_request_duration_count** - Total number of tool requests measured.
* **assisted_service_mcp_tool_request_duration_bucket** - Number of tool requests organized in buckets.

### Metric Labels

All metrics include the following label:
* **tool** - The name of the tool, for example `cluster_info`, `list_clusters`, etc.
