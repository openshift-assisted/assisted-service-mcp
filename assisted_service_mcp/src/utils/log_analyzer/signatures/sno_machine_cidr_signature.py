"""
SNOMachineCidrSignature for OpenShift Assisted Installer logs.
"""

import ipaddress
import json
import logging
from typing import Optional

from .base import Signature, SignatureResult

logger = logging.getLogger(__name__)


class SNOMachineCidrSignature(Signature):
    """Validates machine CIDR configuration for SNO clusters."""

    def analyze(self, log_analyzer) -> Optional[SignatureResult]:
        """Analyze SNO machine CIDR configuration."""
        try:
            metadata = log_analyzer.metadata
            cluster = metadata

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
