"""
Basic information and status signature analysis.
These signatures provide fundamental information about the cluster and installation.
"""

import json
import logging
from collections import OrderedDict, defaultdict
from typing import Optional

from .base import Signature, SignatureResult

logger = logging.getLogger(__name__)


class ComponentsVersionSignature(Signature):
    """Analyzes component versions."""

    def analyze(self, log_analyzer) -> Optional[SignatureResult]:
        """Analyze component versions."""
        try:
            metadata = log_analyzer.metadata
            cluster_md = metadata.get("cluster", {})

            content_lines = []

            release_tag = metadata.get("release_tag") or cluster_md.get("release_tag")
            if release_tag:
                content_lines.append(f"Release tag: {release_tag}")

            versions = metadata.get("versions") or cluster_md.get("versions")
            if versions:
                if "assisted-installer" in versions:
                    content_lines.append(
                        f"assisted-installer: {versions['assisted-installer']}"
                    )
                if "assisted-installer-controller" in versions:
                    content_lines.append(
                        f"assisted-installer-controller: {versions['assisted-installer-controller']}"
                    )
                if "discovery-agent" in versions:
                    content_lines.append(
                        f"assisted-installer-agent: {versions['discovery-agent']}"
                    )

            if content_lines:
                return SignatureResult(
                    signature_name=self.name,
                    title="Component Version Information",
                    content="\n".join(content_lines),
                    severity="info",
                )

        except Exception as e:
            logger.error("Error in ComponentsVersionSignature: %s", e)

        return None


class FailureDescription(Signature):
    """Generates failure description with cluster information."""

    def analyze(self, log_analyzer) -> Optional[SignatureResult]:
        """Analyze and format cluster failure description."""
        try:
            metadata = log_analyzer.metadata
            cluster = metadata["cluster"]

            # Extract key information
            cluster_info = {
                "Cluster ID": cluster["id"],
                "OpenShift Cluster ID": cluster.get("openshift_cluster_id", "N/A"),
                "Username": cluster.get("user_name", "N/A"),
                "Email Domain": cluster.get("email_domain", "N/A"),
                "Created At": self.format_time(cluster["created_at"]),
                "Installation Started At": self.format_time(
                    cluster.get("install_started_at", "")
                ),
                "Failed On": self.format_time(cluster.get("status_updated_at", "")),
                "Status": cluster["status"],
                "Status Info": cluster["status_info"],
                "OpenShift Version": cluster.get("openshift_version", "N/A"),
                "Platform Type": cluster.get("platform", {}).get("type", "N/A"),
            }

            # Format as table
            content = "Cluster Information:\n" + self.generate_table(
                [{"Field": k, "Value": v} for k, v in cluster_info.items()]
            )

            return SignatureResult(
                signature_name=self.name,
                title="Cluster Failure Description",
                content=content,
                severity="info",
            )

        except Exception as e:
            logger.error("Error in FailureDescription: %s", e)
            return None


class HostsExtraDetailSignature(Signature):
    """Provides extra details about hosts."""

    def analyze(self, log_analyzer) -> Optional[SignatureResult]:
        """Analyze host extra details."""
        try:
            metadata = log_analyzer.metadata
            cluster = metadata["cluster"]

            hosts = []
            for host in cluster["hosts"]:
                inventory = json.loads(host["inventory"])
                hosts.append(
                    OrderedDict(
                        id=host["id"],
                        hostname=inventory["hostname"],
                        requested_hostname=host.get("requested_hostname", "N/A"),
                        last_contacted=self.format_time(host["checked_in_at"]),
                        installation_disk=host.get("installation_disk_path", "N/A"),
                        product_name=inventory["system_vendor"].get(
                            "product_name", "Unavailable"
                        ),
                        manufacturer=inventory["system_vendor"].get(
                            "manufacturer", "Unavailable"
                        ),
                        virtual_host=inventory["system_vendor"].get("virtual", False),
                        disks_count=len(inventory["disks"]),
                    )
                )

            content = self.generate_table(hosts)

            return SignatureResult(
                signature_name=self.name,
                title="Host Extra Details",
                content=content,
                severity="info",
            )

        except Exception as e:
            logger.error("Error in HostsExtraDetailSignature: %s", e)
            return None


class HostsInterfacesSignature(Signature):
    """Analyzes host network interfaces."""

    def analyze(self, log_analyzer) -> Optional[SignatureResult]:
        """Analyze host interfaces."""
        try:
            metadata = log_analyzer.metadata
            cluster = metadata["cluster"]

            hosts = []
            for host in cluster["hosts"]:
                interfaces = self._get_interfaces(host)
                hosts.append(
                    OrderedDict(
                        id=host["id"],
                        hostname=log_analyzer.get_hostname(host),
                        name="\n".join(interfaces["name"]),
                        mac_address="\n".join(interfaces["mac_address"]),
                        ipv4_addresses="\n".join(interfaces["ipv4_addresses"]),
                        ipv6_addresses="\n".join(interfaces["ipv6_addresses"]),
                    )
                )

            content = self.generate_table(hosts)

            return SignatureResult(
                signature_name=self.name,
                title="Host Interfaces",
                content=content,
                severity="info",
            )

        except Exception as e:
            logger.error("Error in HostsInterfacesSignature: %s", e)
            return None

    def _get_interfaces(self, host):
        """Extract interface information from host."""
        inventory = json.loads(host["inventory"])
        interfaces_details = defaultdict(list)

        for interface in inventory.get("interfaces", []):
            name = interface.get("name")
            if not name:
                continue
            interfaces_details["name"].append(name)
            interfaces_details["mac_address"].append(
                json.dumps(interface.get("mac_address"))
            )
            interfaces_details["ipv4_addresses"].append(
                json.dumps(interface.get("ipv4_addresses", []))
            )
            interfaces_details["ipv6_addresses"].append(
                json.dumps(interface.get("ipv6_addresses", []))
            )

        return interfaces_details


class StorageDetailSignature(Signature):
    """Analyzes host storage details."""

    def analyze(self, log_analyzer) -> Optional[SignatureResult]:
        """Analyze host storage details."""
        try:
            metadata = log_analyzer.metadata
            cluster = metadata["cluster"]

            hosts = []
            for host in cluster["hosts"]:
                inventory = json.loads(host["inventory"])
                disks = inventory["disks"]

                disks_details = {
                    "type": [],
                    "bootable": [],
                    "name": [],
                    "path": [],
                    "by-path": [],
                }

                for d in disks:
                    disk_type = d.get("drive_type", "Not available")
                    disks_details["type"].append(disk_type)
                    disks_details["bootable"].append(str(d.get("bootable", False)))
                    disks_details["name"].append(d.get("name", "Not available"))
                    disks_details["path"].append(d.get("path", "Not available"))
                    disks_details["by-path"].append(d.get("by_path", "Not available"))

                hosts.append(
                    OrderedDict(
                        **{
                            "Host ID": host["id"],
                            "Hostname": log_analyzer.get_hostname(host),
                            "Disk Name": "\n".join(disks_details["name"]),
                            "Disk Type": "\n".join(disks_details["type"]),
                            "Disk Path": "\n".join(disks_details["path"]),
                            "Disk Bootable": "\n".join(disks_details["bootable"]),
                            "Disk by-path": "\n".join(disks_details["by-path"]),
                        }
                    )
                )

            content = self.generate_table(hosts)

            return SignatureResult(
                signature_name=self.name,
                title="Host Storage Details",
                content=content,
                severity="info",
            )

        except Exception as e:
            logger.error("Error in StorageDetailSignature: %s", e)
            return None
