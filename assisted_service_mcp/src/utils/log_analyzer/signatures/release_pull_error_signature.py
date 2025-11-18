"""
ReleasePullErrorSignature for OpenShift Assisted Installer logs.
"""

import logging
import re
from typing import Optional

from .base import ErrorSignature, SignatureResult
from .helpers import get_hostname

logger = logging.getLogger(__name__)


class ReleasePullErrorSignature(ErrorSignature):
    """Finds clusters where release image cannot be pulled by bootstrap node."""

    ERROR_PATTERN = re.compile(r"release-image-download\.sh\[.+\]: Pull failed")

    def analyze(self, log_analyzer) -> Optional[SignatureResult]:
        hosts_sections = []
        for host, journal_logs in log_analyzer.all_host_journal_logs():
            if self.ERROR_PATTERN.findall(journal_logs):
                hosts_sections.append(
                    f"Release image cannot be pulled on {host['id']} ({get_hostname(host)})"
                )

        if hosts_sections:
            return self.create_result(
                title="Release image cannot be pulled",
                content="\n".join(hosts_sections),
                severity="error",
            )
        return None
