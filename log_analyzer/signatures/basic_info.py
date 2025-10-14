"""
Basic information and status signature analysis.
These signatures provide fundamental information about the cluster and installation.
"""

import json
import logging
from collections import OrderedDict
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
