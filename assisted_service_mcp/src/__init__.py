"""MCP server for Red Hat OpenShift assisted installer.

MCP server for interacting with the OpenShift assisted installer API.
It handles only self-managed OpenShift clusters (OCP and SNO).
It is not handling OCM-managed services such as ROSA, ARO, or OSD - those require a separate MCP server using the OCM API.
"""

__version__ = "0.1.0"
