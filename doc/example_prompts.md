# MCP Tool Example Prompts

This document provides example prompts that would trigger each of the MCP tools available in the Assisted Service API.

## Cluster Management Tools

### `cluster_info`
Get comprehensive information about a specific cluster.

**Example Prompts:**
- "Show me details about my-cluster"
- "What's the status of cluster my-cluster?"

### `list_clusters`
List all clusters for the current user.

**Example Prompts:**
- "Show me all my clusters"
- "List my OpenShift clusters"

### `cluster_events`
Get events related to a specific cluster.

**Example Prompts:**
- "Show me the events for my-cluster"
- "What happened during the installation of cluster my-cluster?"

### `host_events`
Get events specific to a particular host within a cluster.

**Example Prompts:**
- "Show me events for host master-node-1 in my-cluster"
- "What happened to the worker host worker-node-2 in my cluster?"

## Cluster Creation and Configuration

### `create_cluster`
Create a new OpenShift cluster.

**Example Prompts:**
- "Create a new cluster called 'my-cluster' with OpenShift 4.18.2 using domain example.com as a multi-node cluster"
- "I want to create a single-node cluster named 'my-cluster' with version 4.17.1 and base domain edge.local"

### `set_cluster_vips`
Configure virtual IP addresses for cluster API and ingress.

**Example Prompts:**
- "Set the API VIP to 192.168.1.100 and ingress VIP to 192.168.1.101 for my-cluster"
- "Configure cluster my-cluster with API VIP 10.0.0.10 and ingress VIP 10.0.0.11"

### `install_cluster`
Trigger the installation process for a prepared cluster.

**Example Prompts:**
- "Start the installation for my-cluster"

### `set_host_role`
Assign a specific role to a discovered host.

**Example Prompts:**
- "Set host master-node-1 in my-cluster to be a master node"
- "Assign worker role to host worker-node-2 in my-cluster"

## Downloads and Resources

### `cluster_iso_download_url`
Get ISO download URLs for a cluster.

**Example Prompts:**
- "Get the ISO download link for my-cluster"
- "I need the boot ISO URL for cluster my-cluster"

### `cluster_credentials_download_url`
Get presigned download URLs for cluster credential files.

**Example Prompts:**
- "Get the kubeconfig download link for my-cluster"
- "I need the kubeadmin password file for cluster my-cluster"

## Information and Discovery

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
- "Add the virtualization operator bundle to my-cluster"
- "Install the AI operator bundle on cluster my-cluster"
