"""Contextual follow-up question generators for MCP tool responses.

Each function returns a formatted text block of suggested next steps
based on the current state (cluster status, host count, etc.). The LLM
reads these and presents them as a structured numbered list in its reply.
"""

from typing import Any

SETUP_STATUSES = frozenset({"pending-for-input", "insufficient", "ready"})
INSTALLING_STATUSES = frozenset({
    "installing",
    "preparing-for-installation",
    "installing-pending-user-action",
    "finalizing",
})
INSTALLED_STATUSES = frozenset({"installed", "adding-hosts"})
ERROR_STATUSES = frozenset({"error", "cancelled"})


def _format(steps: list[str]) -> str:
    if not steps:
        return ""
    numbered = "\n".join(f"{i}. {s}" for i, s in enumerate(steps, 1))
    return (
        "\n\n[IMPORTANT — After presenting the information above, you MUST "
        "include the following suggested next steps in your response. "
        "Present them exactly as a numbered list under a "
        '"Suggested next steps:" heading.]\n'
        f"{numbered}"
    )


def list_clusters_followups(clusters: list[dict[str, Any]]) -> str:
    """Follow-ups after listing clusters."""
    if not clusters:
        return _format([
            "Create a cluster: would you like to create a new OpenShift cluster?",
        ])

    steps = [
        "Cluster details: get more details about a specific cluster?",
    ]

    has_pending = any(
        c.get("status", "").lower() in SETUP_STATUSES for c in clusters
    )
    if has_pending:
        steps.append(
            "Cluster setup: set up one of the pending clusters?"
        )

    steps.append("New cluster: create a brand new OpenShift cluster?")
    return _format(steps)


def cluster_info_followups(status: str) -> str:
    """Follow-ups after retrieving cluster details, based on status."""
    status = (status or "").lower()
    steps: list[str] = []

    if status in SETUP_STATUSES:
        steps = [
            "Cluster setup: register hosts and configure networking for this cluster?",
            "Pre-install configuration: set an SSH key or add operator bundles before setup?",
            "Readiness check: check what's missing before this cluster can be installed?",
        ]
    elif status in INSTALLING_STATUSES:
        steps = [
            "Installation progress: check the current installation progress?",
            "Troubleshooting: see host-level events to check if any node is having issues?",
        ]
    elif status in INSTALLED_STATUSES:
        steps = [
            "Cluster credentials: download the kubeconfig and kubeadmin password?",
            "Verification: see the final cluster events to confirm everything completed cleanly?",
        ]
    elif status in ERROR_STATUSES:
        steps = [
            "Log analysis: analyze the cluster logs to identify what went wrong?",
            "Event history: see the cluster events to understand the failure?",
        ]

    return _format(steps)


def create_cluster_followups() -> str:
    """Follow-ups after a cluster is successfully created."""
    return _format([
        "Pre-install configuration: add an SSH key or operator bundles "
        "(e.g., OpenShift Virtualization, OpenShift AI) before registering hosts?",
        "Boot a host: download the discovery ISO so you can start booting hosts?",
        "Cluster setup: proceed to the setup wizard to register hosts and configure VIPs?",
    ])


def get_cluster_hosts_followups(
    hosts: list[dict[str, Any]],
    cluster_status: str | None,
) -> str:
    """Follow-ups after retrieving cluster hosts, based on host/cluster state."""
    status = (cluster_status or "").lower()

    if status in INSTALLED_STATUSES:
        return _format([
            "Cluster credentials: download the kubeconfig and kubeadmin password?",
            "Access setup: show the cluster credentials so you can start using the cluster?",
        ])

    if status in INSTALLING_STATUSES:
        return _format([
            "Installation progress: check the current installation progress?",
            "Troubleshooting: see host-specific events to identify any nodes that might be stuck?",
        ])

    if not hosts:
        return _format([
            "Host discovery: have you booted your hosts from the discovery ISO? "
            "They should appear here once they register.",
        ])

    return _format([
        "Role assignment: assign specific roles (master/worker) to the discovered hosts?",
        "Network configuration: configure VIPs (API and Ingress) for this cluster before installing?",
        "Readiness check: check if all host validations are passing before starting installation?",
        "Static networking: configure static networking for any of the hosts?",
    ])


def installation_progress_followups(status: str) -> str:
    """Follow-ups after checking installation progress."""
    status = (status or "").lower()
    steps: list[str] = []

    if status in INSTALLING_STATUSES:
        steps = [
            "Event details: see cluster events for more details on what's happening?",
            "Host troubleshooting: check host-level events for a specific node?",
        ]
    elif status in INSTALLED_STATUSES:
        steps = [
            "Cluster credentials: download the cluster credentials (kubeconfig)?",
        ]
    elif status in ERROR_STATUSES:
        steps = [
            "Log analysis: analyze the cluster logs to identify what went wrong?",
            "Event history: see the cluster events to understand the failure?",
        ]

    return _format(steps)
