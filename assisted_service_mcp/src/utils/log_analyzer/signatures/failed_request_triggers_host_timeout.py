"""
FailedRequestTriggersHostTimeout signature for OpenShift Assisted Installer logs.
"""

import logging
import re
from typing import Optional

from .base import Signature, SignatureResult

logger = logging.getLogger(__name__)


class FailedRequestTriggersHostTimeout(Signature):
    """Look for failed requests that could have caused host timeout."""

    LOG_PATTERN = re.compile(
        r'time="(?P<time>.+)" level=(?P<severity>[a-z]+) msg="(?P<message>.*api\.openshift\.com/api/assisted-install.*Service Unavailable)" file=.+'
    )
    HOST_TIMED_OUT_STATUS_INFO = (
        "Host failed to install due to timeout while connecting to host"
    )

    def analyze(self, log_analyzer) -> Optional[SignatureResult]:
        cluster = log_analyzer.metadata
        failed_requests_hosts = set()
        timed_out_hosts = {
            h["id"]
            for h in cluster.get("hosts", [])
            if h.get("status_info") == self.HOST_TIMED_OUT_STATUS_INFO
        }
        for host in cluster.get("hosts", []):
            try:
                agent_logs = log_analyzer.get_host_log_file(host["id"], "agent.logs")
            except FileNotFoundError:
                continue
            if len(self.LOG_PATTERN.findall(agent_logs)) > 0:
                failed_requests_hosts.add(host["id"])
        intersect = failed_requests_hosts & timed_out_hosts
        if intersect:
            content = "\n".join(
                f"Host {host_id} has request failures and timed out. Did the request cause the host to timeout?"
                for host_id in sorted(intersect)
            )
            return SignatureResult(
                signature_name=self.name,
                title="Failed request triggering host timeout",
                content=content,
                severity="warning",
            )
        if failed_requests_hosts and timed_out_hosts:
            return SignatureResult(
                signature_name=self.name,
                title="Failed request triggering host timeout",
                content=(
                    f"Cluster has at least one host that failed requests ({', '.join(sorted(failed_requests_hosts))}) and at least one host that timed out ({', '.join(sorted(timed_out_hosts))})"
                ),
                severity="warning",
            )
        return None
