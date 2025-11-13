"""
LibvirtRebootFlagSignature for OpenShift Assisted Installer logs.
"""

import json
import logging
from collections import OrderedDict
from typing import Optional

from .base import ErrorSignature, SignatureResult

logger = logging.getLogger(__name__)


class LibvirtRebootFlagSignature(ErrorSignature):
    """Detect potential libvirt _on_reboot_ flag issue (MGMT-2840)."""

    def analyze(self, log_analyzer) -> Optional[SignatureResult]:
        md = log_analyzer.metadata
        cluster = md["cluster"]
        # not relevant for SNO
        if len(cluster.get("hosts", [])) <= 1:
            return None

        hosts = []
        for host in cluster.get("hosts", []):
            inventory = json.loads(host.get("inventory", "{}"))
            if (
                len(inventory.get("disks", [])) == 1
                and "KVM" in inventory.get("system_vendor", {}).get("product_name", "")
                and host.get("progress", {}).get("current_stage") == "Rebooting"
                and host.get("status") == "error"
            ):
                if host.get("role") == "bootstrap":
                    continue
                hosts.append(
                    OrderedDict(
                        id=host["id"],
                        hostname=log_analyzer.get_hostname(host),
                        role=host.get("role"),
                        progress=host.get("progress", {}).get("current_stage"),
                        status=host.get("status"),
                        num_disks=len(inventory.get("disks", [])),
                    )
                )
        if hosts and len(hosts) + 1 == len(cluster.get("hosts", [])):
            return self.create_result(
                title="Potential hosts with libvirt _on_reboot_ flag issue (MGMT-2840)",
                content=self.generate_table(hosts),
                severity="warning",
            )
        return None
