"""
MissingMC signature for OpenShift Assisted Installer logs.
"""

import logging
import re
from typing import Optional

from .base import ErrorSignature, SignatureResult

logger = logging.getLogger(__name__)


class MissingMC(ErrorSignature):
    """Looks for missing MachineConfig error in SNO clusters."""

    def analyze(self, log_analyzer) -> Optional[SignatureResult]:
        if not log_analyzer.cluster_is_sno():
            return None

        path = (
            "controller_logs.tar.gz/must-gather.tar.gz/must-gather.local.*/quay-io-openshift-release-dev-*/cluster-scoped-resources/"
            "machineconfiguration.openshift.io/machineconfigpools/master.yaml"
        )
        try:
            raw = log_analyzer.logs_archive.get(path, mode="rb")
        except FileNotFoundError:
            return None
        try:
            text = raw.decode("utf-8")
        except Exception:
            return None
        if re.search(r"rendered-master-[0-9a-f]{32}.*not found", text) is not None:
            return self.create_result(
                title="Missing MachineConfig issue",
                content="Missing rendered MachineConfig issue detected",
                severity="error",
            )
        return None
