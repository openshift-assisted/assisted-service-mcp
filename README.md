# Assisted Service MCP Server

MCP server for interacting with the OpenShift assisted installer API.

Diagnose cluster failures and find out how to fix them.

Try it out:

1. Clone the repo:
```
git clone git@github.com:carbonin/assisted-service-mcp.git
```

2. Get your OpenShift API token from https://cloud.redhat.com/openshift/token

3. The server is started and configured differently depending on what transport you want to use

For STDIO:

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
                    "/path/to/assisted-service-mcp/server.py"
                ],
                "env": {
                    "OFFLINE_TOKEN": <your token>
                }
            }
        }
    }
```

For SSE (recommended):

Start the server in a terminal:

`OFFLINE_TOKEN=<your token> uv run server.py`

Configure the server in the client:

```json
    "assisted-sse": {
      "transport": "sse",
      "url": "http://localhost:8000/sse"
    }
```

4. Ask about your clusters:
![Example prompt asking about a cluster](images/cluster-prompt-example.png)

### Providing the Offline Token via Request Header

If you do not set the `OFFLINE_TOKEN` environment variable, you can provide the token as a request header.
When configuring your MCP client, add the `OCM-Offline-Token` header:

```json
    "assisted-sse": {
      "transport": "sse",
      "url": "http://localhost:8000/sse",
      "headers": {
        "OCM-Offline-Token": "<your token>"
      }
    }
```

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

### Infrastructure Environment

* **infraenv_info** - Get detailed information about the assisted installer infra env with the given ID. Contains data like ISO download URL and infra env metadata.
  * `infraenv_id`: Infrastructure environment ID (string, required)

### Host Management

* **set_host_role** - Update a host to a specific role. Role options are: 'auto-assign', 'master', 'arbiter', 'worker'
  * `host_id`: Host ID (string, required)
  * `infraenv_id`: Infrastructure environment ID (string, required)
  * `role`: Host role (string, required)

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

## Authorization Options

The server supports multiple authorization methods for accessing the Assisted Installer API. The
method used depends on the environment variables and headers you provide. The following methods are
checked in order of priority; the first one that succeeds will be used, and the rest will be
ignored:

### 1. Access token in the `Authorization` request header

If the `Authorization` request header contains a bearer token, it will be passed directly to the
Assisted Installer API. In this case, the OAuth flow will not be triggered, and any values provided
in the `OFFLINE_TOKEN` environment variable or the `OCM-Offline-Token` request header will be
ignored.

### 2. OAuth flow

If the `OAUTH_ENABLED` environment variable is set to `true`, the server will use a subset of the
OAuth protocol that MCP clients (such as the one in VS Code) use for authentication. When you
attempt to connect, the MCP client will open a browser window where you can enter your credentials.
The client will then request an access token, which the server will use to authenticate requests to
the Assisted Installer API.

When using this authentication method, the `OFFLINE_TOKEN` environment variable and the
`OCM-Offline-Token` header will be ignored.

You can configure the OAuth authorization server and client identifier using the `OAUTH_URL` and
`OAUTH_CLIENT` environment variables. The default values are:

- `OAUTH_URL`: `https://sso.redhat.com/auth/realms/redhat-external`
- `OAUTH_CLIENT`: `cloud-services`

The `SELF_URL` environment variable specifies the base URL that the server uses to construct URLs
referencing itself. For example, when OAuth is enabled, the server will generate the dynamic client
registration URL by appending `/oauth/register` to this base URL. The default value is
`http://localhost:8000`, but in production environments, it should be set to the actual URL of the
server as accessible to clients. For instance, if the server is accessed through a reverse proxy
using HTTPS and the host `my.host.com`, the value should be set to `https://my.host.com`.

### 3. Offline token via environment variable

If you set the `OFFLINE_TOKEN` environment variable, the server will use this offline token to
request an access token, which will then be used to call the Assisted Installer API.

### 4. Offline token via request header

If the `OCM-Offline-Token` request header is set, the server will use it to request an access token,
and will then use that access token to call the Assisted Installer API.