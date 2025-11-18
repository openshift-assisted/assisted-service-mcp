"""
DualstackrDNSBug signature for OpenShift Assisted Installer logs.
"""

import logging
from typing import Optional

from assisted_service_mcp.src.utils.log_analyzer.log_analyzer import (
    LOG_BUNDLE_PATH,
)

from .base import ErrorSignature, SignatureResult

logger = logging.getLogger(__name__)


class DualstackrDNSBug(ErrorSignature):
    """Detect kube-apiserver 'must match public address family' message (MGMT-11651)."""

    def analyze(self, log_analyzer) -> Optional[SignatureResult]:
        path = f"{LOG_BUNDLE_PATH}/bootstrap/containers/kube-apiserver-*.log"
        try:
            kubeapiserver_logs = log_analyzer.logs_archive.get(path)
        except FileNotFoundError:
            return None
        if "must match public address family" in kubeapiserver_logs:
            return self.create_result(
                title="rDNS and DNS entries for IPv4/IPv6 interface - MGMT-11651",
                content=(
                    "kube-apiserver logs contain the message 'must match public address family', this is probably due to MGMT-11651"
                ),
                severity="warning",
            )
        return None
