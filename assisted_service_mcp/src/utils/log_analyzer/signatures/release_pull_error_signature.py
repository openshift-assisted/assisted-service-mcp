"""
ReleasePullErrorSignature for OpenShift Assisted Installer logs.
"""

import logging
import re
from typing import Optional

from .base import ErrorSignature, SignatureResult

logger = logging.getLogger(__name__)


class ReleasePullErrorSignature(ErrorSignature):
    """Finds clusters where release image cannot be pulled by bootstrap node."""

    ERROR_PATTERN = re.compile(r"release-image-download\.sh\[.+\]: Pull failed")

    def analyze(self, log_analyzer) -> Optional[SignatureResult]:
        try:
            cluster = log_analyzer.metadata["cluster"]
        except Exception:
            return None

        hosts_sections = []
        for host in cluster.get("hosts", []):
            host_id = host["id"]
            try:
                journal_logs = log_analyzer.get_host_log_file(host_id, "journal.logs")
            except FileNotFoundError:
                continue
            if self.ERROR_PATTERN.findall(journal_logs):
                hosts_sections.append(
                    f"Release image cannot be pulled on {host_id} ({log_analyzer.get_hostname(host)})"
                )

        if hosts_sections:
            return self.create_result(
                title="Release image cannot be pulled",
                content="\n".join(hosts_sections),
                severity="error",
            )
        return None
