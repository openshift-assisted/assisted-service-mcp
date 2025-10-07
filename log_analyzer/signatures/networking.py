"""
Networking analysis signatures for OpenShift Assisted Installer logs.
These signatures analyze network configuration and connectivity issues.
"""

import json
import logging
import ipaddress
import os
import re
from typing import Optional

from log_analyzer.log_analyzer import NEW_LOG_BUNDLE_PATH, OLD_LOG_BUNDLE_PATH
from log_analyzer.signatures.advanced_analysis import (
    operator_statuses_from_controller_logs,
    filter_operators,
)

from .base import Signature, ErrorSignature, SignatureResult

logger = logging.getLogger(__name__)


class SNOMachineCidrSignature(Signature):
    """Validates machine CIDR configuration for SNO clusters."""

    def analyze(self, log_analyzer) -> Optional[SignatureResult]:
        """Analyze SNO machine CIDR configuration."""
        try:
            metadata = log_analyzer.metadata
            cluster = metadata["cluster"]

            if cluster.get("high_availability_mode") != "None":
                return None

            if not cluster.get("hosts"):
                return None
            host = cluster["hosts"][0]
            inventory = json.loads(host["inventory"])

            # The first one is the machine_cidr that will be used for network configuration
            machine_cidr = ipaddress.ip_network(cluster["machine_networks"][0]["cidr"])

            for route in inventory.get("routes", []):
                # currently only relevant for ipv4
                if (
                    route.get("destination") == "0.0.0.0"
                    and route.get("gateway")
                    and ipaddress.ip_address(route["gateway"]) in machine_cidr
                ):
                    return None

            content = (
                f"Machine cidr {machine_cidr} doesn't match any default route configured on the host.\n"
                f"It will cause etcd certificate error (or some other) as kubelet and OVNKubernetes will not run with expected machine cidr.\n"
                f"We hope it will be fixed after https://issues.redhat.com/browse/SDN-3053"
            )

            return SignatureResult(
                signature_name=self.name,
                title="Invalid Machine CIDR",
                content=content,
                severity="error",
            )

        except Exception as e:
            logger.error("Error in SNOMachineCidrSignature: %s", e)
            return None


class DuplicateVIP(ErrorSignature):
    """Looks for nodes holding the same VIP."""

    # pylint: disable=too-many-nested-blocks,too-many-branches
    def analyze(self, log_analyzer) -> Optional[SignatureResult]:
        """Analyze for duplicate VIP issues."""
        try:
            cluster = log_analyzer.metadata["cluster"]

            # SNO doesn't need balancing
            if cluster.get("high_availability_mode") == "None":
                return None

            # VIPs are not relevant with load balancer
            if cluster.get("user_managed_networking") is True:  # noqa: E712
                return None

            vips = [vip["ip"] for vip in cluster.get("api_vips", [])]
            if not vips:
                return None

            collisions = []
            # Check control-plane nodes
            try:
                control_plane_dir = log_analyzer.logs_archive.get(
                    f"{NEW_LOG_BUNDLE_PATH}/control-plane/"
                )
                for node_dir in getattr(control_plane_dir, "iterdir", lambda: [])():
                    node_ip = os.path.basename(node_dir)
                    try:
                        ip_addr = log_analyzer.logs_archive.get(
                            f"{NEW_LOG_BUNDLE_PATH}/control-plane/{node_ip}/network/ip-addr.txt"
                        )
                    except FileNotFoundError:
                        continue
                    for vip in vips:
                        if vip in ip_addr:
                            collisions.append((vip, node_ip))
            except FileNotFoundError:
                pass

            # Check bootstrap
            try:
                bootstrap_ip_addr = log_analyzer.logs_archive.get(
                    f"{NEW_LOG_BUNDLE_PATH}/bootstrap/network/ip-addr.txt"
                )
                for vip in vips:
                    if vip in bootstrap_ip_addr:
                        collisions.append((vip, "bootstrap"))
            except FileNotFoundError:
                pass

            # Fallback to OLD path
            if not collisions:
                try:
                    control_plane_dir = log_analyzer.logs_archive.get(
                        f"{OLD_LOG_BUNDLE_PATH}/control-plane/"
                    )
                    for node_dir in getattr(control_plane_dir, "iterdir", lambda: [])():
                        node_ip = os.path.basename(node_dir)
                        try:
                            ip_addr = log_analyzer.logs_archive.get(
                                f"{OLD_LOG_BUNDLE_PATH}/control-plane/{node_ip}/network/ip-addr.txt"
                            )
                        except FileNotFoundError:
                            continue
                        for vip in vips:
                            if vip in ip_addr:
                                collisions.append((vip, node_ip))
                except FileNotFoundError:
                    pass

                try:
                    bootstrap_ip_addr = log_analyzer.logs_archive.get(
                        f"{OLD_LOG_BUNDLE_PATH}/bootstrap/network/ip-addr.txt"
                    )
                    for vip in vips:
                        if vip in bootstrap_ip_addr:
                            collisions.append((vip, "bootstrap"))
                except FileNotFoundError:
                    pass

            # Aggregate per VIP
            vip_to_nodes = {}
            for vip, node in collisions:
                vip_to_nodes.setdefault(vip, set()).add(node)

            dup_msgs = [
                f"Found duplicate VIP {vip} in control-plane hosts {' and '.join(sorted(nodes))}"
                for vip, nodes in vip_to_nodes.items()
                if len(nodes) > 1
            ]

            if dup_msgs:
                return self.create_result(
                    title="VIP found in multiple nodes",
                    content="\n".join(dup_msgs),
                    severity="error",
                )
            return None

        except Exception as e:
            logger.error("Error in DuplicateVIP: %s", e)

        return None


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
            for node_dir in getattr(control_plane_dir, "iterdir", lambda: [])():
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
        cidrs = [
            network["cidr"] for network in md["cluster"].get("cluster_networks", [])
        ]
        if not cidrs:
            return None

        report_lines = []
        for base in (NEW_LOG_BUNDLE_PATH, OLD_LOG_BUNDLE_PATH):
            nameservers = self._get_nameservers(log_analyzer, base)
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


class NetworksMtuMismatch(ErrorSignature):
    """Detect MTU mismatch between interface and overlay network."""

    LOG_PATTERN = re.compile(
        r"Failed to start sdn: interface MTU [(]([0-9]+)[)] is too small for specified overlay MTU [(]([0-9]+)[)]"
    )

    def analyze(self, log_analyzer) -> Optional[SignatureResult]:
        path = "controller_logs.tar.gz/must-gather.tar.gz/must-gather.local.*/*/namespaces/openshift-sdn/pods/sdn-*/sdn/sdn/logs/*.log"
        try:
            sdn_logs = log_analyzer.logs_archive.get(path)
        except FileNotFoundError:
            return None
        m = self.LOG_PATTERN.search(sdn_logs)
        if m:
            return self.create_result(
                title="Networks MTU Mismatch",
                content=f"SDN failed to start: Overlay (cluster) network MTU {m.group(2)} is bigger than the interface MTU {m.group(1)}",
                severity="error",
            )
        return None


class DualStackBadRoute(ErrorSignature):
    """Looks for BZ 2088346 in ovnkube-node logs."""

    fatal_error_regex = re.compile(
        r"^F.*failed to get default gateway interface$", re.MULTILINE
    )

    def analyze(self, log_analyzer) -> Optional[SignatureResult]:
        for base in (NEW_LOG_BUNDLE_PATH, OLD_LOG_BUNDLE_PATH):
            path = f"{base}/control-plane/*/containers/ovnkube-node-*.log"
            try:
                ovnkube_logs = log_analyzer.logs_archive.get(path)
            except FileNotFoundError:
                continue
            if self.fatal_error_regex.search(ovnkube_logs):
                return self.create_result(
                    title="Bugzilla 2088346",
                    content="ovnkube-node logs indicate the cluster may be hitting BZ 2088346",
                    severity="error",
                )
        return None


class DualstackrDNSBug(ErrorSignature):
    """Detect kube-apiserver 'must match public address family' message (MGMT-11651)."""

    def analyze(self, log_analyzer) -> Optional[SignatureResult]:
        for base in (NEW_LOG_BUNDLE_PATH, OLD_LOG_BUNDLE_PATH):
            path = f"{base}/bootstrap/containers/kube-apiserver-*.log"
            try:
                kubeapiserver_logs = log_analyzer.logs_archive.get(path)
            except FileNotFoundError:
                continue
            if "must match public address family" in kubeapiserver_logs:
                return self.create_result(
                    title="rDNS and DNS entries for IPv4/IPv6 interface - MGMT-11651",
                    content=(
                        "kube-apiserver logs contain the message 'must match public address family', this is probably due to MGMT-11651"
                    ),
                    severity="warning",
                )
        return None


class UserManagedNetworkingLoadBalancer(ErrorSignature):
    """Detects UMN clusters where load-balancer related operators are the only unhealthy ones."""

    lb_operators = {"authentication", "console", "ingress"}

    def analyze(self, log_analyzer) -> Optional[SignatureResult]:
        metadata = log_analyzer.metadata
        cluster_md = metadata.get("cluster", {})

        if not cluster_md.get("user_managed_networking", False):
            return None

        if cluster_md.get("high_availability_mode") == "None":
            return None

        try:
            controller_logs = log_analyzer.get_controller_logs()
        except FileNotFoundError:
            return None

        operator_statuses = operator_statuses_from_controller_logs(controller_logs)

        unhealthy_operators = filter_operators(
            operator_statuses,
            (("Degraded", True), ("Available", False), ("Progressing", True)),
            aggregation_function=any,
        )

        unhealthy_keys = set(unhealthy_operators.keys())
        if unhealthy_keys and unhealthy_keys.issubset(self.lb_operators):
            content = "Cluster has user-managed networking and only load-balancer related operators seem to be unhealthy."
            if missing := self.lb_operators - unhealthy_keys:
                content += f" Operators missing from unhealthy set: {', '.join(sorted(missing))}."
            return self.create_result(
                title="Probably user managed load-balancer issues",
                content=content,
                severity="warning",
            )

        return None
