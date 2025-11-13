"""
ErrorOnCleanupInstallDevice signature for OpenShift Assisted Installer logs.
"""

import logging
import re
from collections import OrderedDict
from typing import Optional

from .base import ErrorSignature, SignatureResult

logger = logging.getLogger(__name__)


class ErrorOnCleanupInstallDevice(ErrorSignature):
    """Detect non-fatal errors during cleanupInstallDevice in installer logs."""

    LOG_PATTERN = re.compile(r'msg="(?P<message>failed to prepare install device.*)"')

    def analyze(self, log_analyzer) -> Optional[SignatureResult]:
        cluster = log_analyzer.metadata.get("cluster", {})
        hosts = []
        for host in cluster.get("hosts", []):
            host_id = host["id"]
            try:
                installer_logs = log_analyzer.get_host_log_file(
                    host_id, "installer.logs"
                )
            except FileNotFoundError:
                continue
            match = self.LOG_PATTERN.search(installer_logs)
            if match:
                hosts.append(
                    OrderedDict(
                        host=log_analyzer.get_hostname(host),
                        message=match.group("message"),
                    )
                )
        if hosts:
            content = "cleanupInstallDevice function has failed for the following hosts. However, its failure does not block installation. Check logs to see if it is related to the installation failure\n"
            content += self.generate_table(hosts)
            return self.create_result(
                title="Non-fatal error on cleanupInstallDevice",
                content=content,
                severity="warning",
            )
        return None
