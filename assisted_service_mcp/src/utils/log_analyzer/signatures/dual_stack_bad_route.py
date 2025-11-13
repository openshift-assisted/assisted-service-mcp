"""
DualStackBadRoute signature for OpenShift Assisted Installer logs.
"""

import logging
import re
from typing import Optional

from assisted_service_mcp.src.utils.log_analyzer.log_analyzer import (
    LOG_BUNDLE_PATH,
)

from .base import ErrorSignature, SignatureResult

logger = logging.getLogger(__name__)


class DualStackBadRoute(ErrorSignature):
    """Looks for BZ 2088346 in ovnkube-node logs."""

    fatal_error_regex = re.compile(
        r"^F.*failed to get default gateway interface$", re.MULTILINE
    )

    def analyze(self, log_analyzer) -> Optional[SignatureResult]:
        path = f"{LOG_BUNDLE_PATH}/control-plane/*/containers/ovnkube-node-*.log"
        try:
            ovnkube_logs = log_analyzer.logs_archive.get(path)
        except FileNotFoundError:
            return None
        if self.fatal_error_regex.search(ovnkube_logs):
            return self.create_result(
                title="Bugzilla 2088346",
                content="ovnkube-node logs indicate the cluster may be hitting BZ 2088346",
                severity="error",
            )
        return None
