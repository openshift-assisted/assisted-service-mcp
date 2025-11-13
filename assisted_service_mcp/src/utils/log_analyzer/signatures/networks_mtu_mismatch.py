"""
NetworksMtuMismatch signature for OpenShift Assisted Installer logs.
"""

import logging
import re
from typing import Optional

from .base import ErrorSignature, SignatureResult

logger = logging.getLogger(__name__)


class NetworksMtuMismatch(ErrorSignature):
    """Detect MTU mismatch between interface and overlay network."""

    LOG_PATTERN = re.compile(
        r"Failed to start sdn: interface MTU [(]([0-9]+)[)] is too small for specified overlay MTU [(]([0-9]+)[)]"
    )

    def analyze(self, log_analyzer) -> Optional[SignatureResult]:
        path = "controller_logs.tar.gz/must-gather.tar.gz/must-gather.local.*/quay-io-openshift-release-dev-*/namespaces/openshift-sdn/pods/sdn-*/sdn/sdn/logs/*.log"
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
