"""
DuplicateVIP signature for OpenShift Assisted Installer logs.
"""

import logging
import os
from typing import Optional

from assisted_service_mcp.src.utils.log_analyzer.log_analyzer import (
    LOG_BUNDLE_PATH,
)

from .base import ErrorSignature, SignatureResult

logger = logging.getLogger(__name__)


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
                    f"{LOG_BUNDLE_PATH}/control-plane/"
                )
                for node_dir in self.archive_dir_contents(control_plane_dir):
                    node_ip = os.path.basename(node_dir)
                    try:
                        ip_addr = log_analyzer.logs_archive.get(
                            f"{LOG_BUNDLE_PATH}/control-plane/{node_ip}/network/ip-addr.txt"
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
                    f"{LOG_BUNDLE_PATH}/bootstrap/network/ip-addr.txt"
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
