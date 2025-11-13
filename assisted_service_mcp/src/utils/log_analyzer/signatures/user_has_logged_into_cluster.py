"""
UserHasLoggedIntoCluster signature for OpenShift Assisted Installer logs.
"""

import logging
import re
from typing import Optional

from .base import Signature, SignatureResult

logger = logging.getLogger(__name__)


class UserHasLoggedIntoCluster(Signature):
    """Detect user login to cluster nodes during installation."""

    USER_LOGIN_PATTERN = re.compile(
        r"pam_unix\((sshd|login):session\): session opened for user .+ by"
    )

    def analyze(self, log_analyzer) -> Optional[SignatureResult]:
        cluster = log_analyzer.metadata.get("cluster", {})
        msgs = []
        for host in cluster.get("hosts", []):
            host_id = host["id"]
            try:
                journal_logs = log_analyzer.get_host_log_file(host_id, "journal.logs")
            except FileNotFoundError:
                continue
            if self.USER_LOGIN_PATTERN.findall(journal_logs):
                msgs.append(
                    f"Host {host_id}: found evidence of a user login during installation. This might indicate that some settings have been changed manually; if incorrect they could contribute to failure."
                )
        if msgs:
            return SignatureResult(
                signature_name=self.name,
                title="User has logged into cluster nodes during installation",
                content="\n".join(msgs),
                severity="warning",
            )
        return None
