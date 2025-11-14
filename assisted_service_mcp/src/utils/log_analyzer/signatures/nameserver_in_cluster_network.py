"""
NameserverInClusterNetwork signature for OpenShift Assisted Installer logs.
"""

import ipaddress
import logging
import os
import re
from typing import Optional

from assisted_service_mcp.src.utils.log_analyzer.log_analyzer import (
    LOG_BUNDLE_PATH,
)

from .base import ErrorSignature, SignatureResult

logger = logging.getLogger(__name__)


class NameserverInClusterNetwork(ErrorSignature):
    """Detect nameservers that overlap with cluster networks."""

    NAMESERVER_PATTERN = re.compile(r"^nameserver (.*)$")

    def _get_nameservers(self, log_analyzer, base_path: str):
        nameservers = set()
        # control-plane
        try:
            control_plane_dir = log_analyzer.logs_archive.get(
                f"{base_path}/control-plane/"
            )
            for node_dir in self.archive_dir_contents(control_plane_dir):
                node_ip = os.path.basename(node_dir)
                try:
                    resolvconf = log_analyzer.logs_archive.get(
                        f"{base_path}/control-plane/{node_ip}/network/resolv.conf"
                    )
                except FileNotFoundError:
                    continue
                for line in resolvconf.splitlines():
                    m = self.NAMESERVER_PATTERN.search(line)
                    if m:
                        nameservers.add(m.group(1))
        except FileNotFoundError:
            pass
        # bootstrap
        try:
            resolvconf = log_analyzer.logs_archive.get(
                f"{base_path}/bootstrap/network/resolv.conf"
            )
            for line in resolvconf.splitlines():
                m = self.NAMESERVER_PATTERN.search(line)
                if m:
                    nameservers.add(m.group(1))
        except FileNotFoundError:
            pass
        return nameservers

    def analyze(self, log_analyzer) -> Optional[SignatureResult]:
        md = log_analyzer.metadata
        cidrs = [network["cidr"] for network in md.get("cluster_networks", [])]
        if not cidrs:
            return None

        report_lines = []
        nameservers = self._get_nameservers(log_analyzer, LOG_BUNDLE_PATH)
        for ns in nameservers:
            for cidr in cidrs:
                try:
                    if ipaddress.ip_address(ns) in ipaddress.ip_network(
                        cidr, strict=False
                    ):
                        report_lines.append(
                            f"User defined nameserver {ns} overlaps with the cluster network {cidr}"
                        )
                except ValueError:
                    continue
        if report_lines:
            return self.create_result(
                title="Nameserver in internal network",
                content="\n".join(sorted(set(report_lines))),
                severity="error",
            )
        return None
