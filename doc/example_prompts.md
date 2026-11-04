# MCP Tool Example Prompts

This document provides example prompts that would trigger each of the MCP tools available in the Assisted Service API.

## Cluster Management

### `list_clusters`
List all clusters for the current user.

**Example Prompts:**
- "Show me all my clusters"
- "List my OpenShift clusters"

### `cluster_info`
Get comprehensive information about a specific cluster.

**Example Prompts:**
- "Show me details about cluster abc123"
- "What's the status of cluster abc123?"

### `create_cluster`
Create a new OpenShift cluster.

**Example Prompts:**
- "Create a multi-node cluster named 'my-cluster' with OpenShift 4.18.2, base domain example.com, and single_node set to false"
- "Create a single-node cluster named 'my-cluster' with OpenShift 4.17.1, base domain edge.local, and single_node set to true"

### `install_cluster`
Trigger the installation process for a prepared cluster.

**Example Prompts:**
- "Start the installation for cluster abc123"

### `cluster_credentials_download_url`
Get a presigned download URL for a cluster credential file.

**Example Prompts:**
- "Get the kubeconfig download link for cluster abc123"
- "Get the kubeadmin password file download link for cluster abc123"

### `set_cluster_platform`
Set or update the infrastructure platform for an existing cluster. Valid platforms are `baremetal`, `vsphere`, `oci`, `nutanix`, and `none`.

**Example Prompts:**
- "Set the platform for cluster abc123 to vsphere"
- "Set cluster abc123's platform to none"

## Events and Monitoring

### `cluster_events`
Get events related to a specific cluster.

**Example Prompts:**
- "Show me the events for cluster abc123"
- "What happened during the installation of cluster abc123?"

### `host_events`
Get events specific to a particular host within a cluster.

**Example Prompts:**
- "Show me events for host master-node-1 in cluster abc123"
- "What happened to host worker-node-2 in cluster abc123?"

### `cluster_logs_download_url`
Get a presigned URL to download the cluster log bundle.

**Example Prompts:**
- "Get the log bundle download link for cluster abc123"
- "Give me a URL to download logs for cluster abc123"

### `analyze_cluster_logs`
Analyze available Assisted Installer logs for a cluster and summarize detected issues. This tool is available only when the service operator enables troubleshooting tools.

**Example Prompts:**
- "Analyze the logs for cluster abc123 and summarize any installation issues"
- "Find errors in the Assisted Installer logs for cluster abc123"

## ISO Download URL

### `cluster_iso_download_url`
Get ISO download URLs for a cluster.

**Example Prompts:**
- "Get the ISO download link for cluster abc123"
- "I need the boot ISO URL for cluster abc123"

## Host Management

### `set_host_role`
Assign a specific role to a discovered host. Valid roles are `auto-assign`, `master`, and `worker`.

**Example Prompts:**
- "Set host master-node-1 in cluster abc123 to the master role"
- "Assign the worker role to host worker-node-2 in cluster abc123"

## Network Configuration

### `set_cluster_vips`
Configure virtual IP addresses for the cluster API and ingress.

**Example Prompts:**
- "Set the API VIP to 192.168.1.100 and ingress VIP to 192.168.1.101 for cluster abc123"
- "Configure cluster abc123 with API VIP 10.0.0.10 and ingress VIP 10.0.0.11"

### `validate_nmstate_yaml`
Validate NMState YAML syntax before applying it to hosts.

**Example Prompts:**
- "Validate this NMState YAML before I apply it: [paste YAML]"
- "Check whether this static network configuration YAML is valid: [paste YAML]"

### `generate_nmstate_yaml`
Generate NMState YAML from structured network parameters.

**Example Prompts:**
- "Generate NMState YAML for interface eth0 with MAC address 00:11:22:33:44:55, static IPv4 address 192.168.1.20/24, and DNS server 192.168.1.1"
- "Create NMState YAML for my host's Ethernet interface, static IP, gateway, and DNS settings: [provide the interface and network values]"

### `alter_static_network_config_nmstate_for_host`
Add, replace, or remove a host's static network configuration for a cluster.

**Example Prompts:**
- "Add this validated NMState YAML as a new host configuration for cluster abc123: [paste YAML]"
- "Replace static network configuration 0 for cluster abc123 with this validated NMState YAML: [paste YAML]"
- "Remove static network configuration 1 from cluster abc123"

### `list_static_network_config`
List the static network configurations for a cluster.

**Example Prompts:**
- "List the static network configurations for cluster abc123"
- "Show me the static network configuration assigned to each host in cluster abc123"

## SSH Key Management

### `set_cluster_ssh_key`
Set or update the SSH public key for a cluster to allow SSH access to its nodes.

**Example Prompts:**
- "Set the SSH key for cluster abc123 to ssh-rsa AAAAB3NzaC1yc2E..."

## OpenShift Versions and Operators

### `list_versions`
List all available OpenShift versions.

**Example Prompts:**
- "What OpenShift versions are available?"
- "Show me all the OpenShift versions I can install"

### `list_operator_bundles`
List available operator bundles.

**Example Prompts:**
- "What operator bundles are available?"
- "Show me all the operators I can install"

### `add_operator_bundle_to_cluster`
Add an operator bundle to be installed with the cluster.

**Example Prompts:**
- "Add the virtualization operator bundle to cluster abc123 before installation"
- "Add the AI operator bundle to cluster abc123 before starting installation"
