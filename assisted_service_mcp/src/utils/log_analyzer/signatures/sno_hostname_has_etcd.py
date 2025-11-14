"""
SNOHostnameHasEtcd signature for OpenShift Assisted Installer logs.
"""

import logging
from typing import Optional

from .base import ErrorSignature, SignatureResult

logger = logging.getLogger(__name__)


class SNOHostnameHasEtcd(ErrorSignature):
    """Looks for etcd in SNO hostname (OCPBUGS-15852)."""

    def analyze(self, log_analyzer) -> Optional[SignatureResult]:
        """Analyze SNO hostname for etcd."""
        try:
            if not log_analyzer.cluster_is_sno():
                return None

            cluster = log_analyzer.metadata
            if len(cluster["hosts"]) != 1:
                return None

            hostname = log_analyzer.get_hostname(cluster["hosts"][0])
            if "etcd" in hostname:
                content = "Hostname cannot contain etcd, see https://issues.redhat.com/browse/OCPBUGS-15852"

                return self.create_result(
                    title="No etcd in SNO hostname", content=content, severity="error"
                )

        except Exception as e:
            logger.error("Error in SNOHostnameHasEtcd: %s", e)

        return None
