"""
Platform-specific signatures for OpenShift Assisted Installer logs.
These signatures analyze issues specific to certain platforms or virtualization technologies.
"""

import gzip
import ipaddress
import json
import logging
import re
from collections import OrderedDict
from typing import Optional

from .base import ErrorSignature, SignatureResult

logger = logging.getLogger(__name__)


class LibvirtRebootFlagSignature(ErrorSignature):
    """Detect potential libvirt _on_reboot_ flag issue (MGMT-2840)."""

    logs_required = False

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


class IpChangedAfterReboot(ErrorSignature):
    """Detect if IP changed after reboot based on journals and inventory."""

    agent_log_regex = re.compile(
        r"Sending step <inventory-[0-9a-f]{8}> reply output <(.+)> error <.*> exit-code <0>"
    )
    journal_lease_regex = re.compile(r"state changed new lease, address=([^ \n]*)")

    def _get_inventory(self, log_analyzer, host_id):
        try:
            agent_logs = log_analyzer.get_host_log_file(host_id, "agent.logs")
        except FileNotFoundError:
            return None
        match = self.agent_log_regex.search(agent_logs)
        return json.loads(match.group(1).replace('\\"', '"')) if match else None

    def _get_address_map(self, inventory):
        address_map = {}
        interfaces = inventory.get("interfaces")
        if interfaces:
            for interface in interfaces:
                for key in ["ipv4_addresses", "ipv6_addresses"]:
                    addresses = interface.get(key)
                    if addresses:
                        for addr in addresses:
                            intf = ipaddress.ip_interface(addr)
                            address_map[str(intf.ip)] = str(intf.network)
        return address_map

    def analyze(self, log_analyzer) -> Optional[SignatureResult]:
        md = log_analyzer.metadata
        cluster = md["cluster"]

        for host in cluster.get("hosts", []):
            host_id = host["id"]
            inventory = self._get_inventory(log_analyzer, host_id)
            if not inventory:
                continue
            address_map = self._get_address_map(inventory)
            if not address_map:
                continue
            for addr, n in address_map.items():
                try:
                    journal_gz = log_analyzer.get_journal_log(
                        addr, "journal.log.gz", mode="rb"
                    )
                    journal = gzip.decompress(journal_gz).decode(
                        "utf-8", errors="ignore"
                    )
                except FileNotFoundError:
                    continue
                for match in self.journal_lease_regex.finditer(journal):
                    cidr = address_map.get(match.group(1))
                    if not cidr:
                        ipaddr = ipaddress.ip_address(match.group(1))
                        if ipaddr in ipaddress.ip_network(n):
                            return self.create_result(
                                title="Ip changed after reboot",
                                content=(
                                    f"Discovered address {addr} changed by leased address {match.group(1)} after reboot for host {host_id}"
                                ),
                                severity="warning",
                            )
        return None
