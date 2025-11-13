"""
MachineConfigDaemonErrorExtracting signature for OpenShift Assisted Installer logs.
"""

import logging
import re
from typing import Optional

from assisted_service_mcp.src.utils.log_analyzer.log_analyzer import (
    LOG_BUNDLE_PATH,
)

from .base import Signature, SignatureResult

logger = logging.getLogger(__name__)


class MachineConfigDaemonErrorExtracting(Signature):
    """Looks for MCD firstboot extraction error (OCPBUGS-5352)."""

    mco_error = re.compile(
        r"must be empty, pass --confirm to overwrite contents of directory$",
        re.MULTILINE,
    )

    def analyze(self, log_analyzer) -> Optional[SignatureResult]:
        path = f"{LOG_BUNDLE_PATH}/control-plane/*/journals/machine-config-daemon-firstboot.log"
        try:
            mcd_logs = log_analyzer.logs_archive.get(path)
        except FileNotFoundError:
            return None
        if self.mco_error.search(mcd_logs):
            return SignatureResult(
                signature_name=self.name,
                title="machine-config-daemon could not extract machine-os-content",
                content=(
                    "machine-config-daemon-firstboot logs indicate a node may be hitting OCPBUGS-5352"
                ),
                severity="warning",
            )
        return None
