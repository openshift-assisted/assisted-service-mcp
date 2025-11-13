"""
UserManagedNetworkingLoadBalancer signature for OpenShift Assisted Installer logs.
"""

import logging
from typing import Optional

from assisted_service_mcp.src.utils.log_analyzer.signatures.helpers import (
    operator_statuses_from_controller_logs,
    filter_operators,
)

from .base import ErrorSignature, SignatureResult

logger = logging.getLogger(__name__)


class UserManagedNetworkingLoadBalancer(ErrorSignature):
    """Detects UMN clusters where load-balancer related operators are the only unhealthy ones."""

    lb_operators = {"authentication", "console", "ingress"}

    def analyze(self, log_analyzer) -> Optional[SignatureResult]:
        metadata = log_analyzer.metadata
        cluster_md = metadata.get("cluster", {})

        if not cluster_md.get("user_managed_networking", False):
            return None

        if cluster_md.get("high_availability_mode") == "None":
            return None

        try:
            controller_logs = log_analyzer.get_controller_logs()
        except FileNotFoundError:
            return None

        operator_statuses = operator_statuses_from_controller_logs(controller_logs)

        unhealthy_operators = filter_operators(
            operator_statuses,
            (("Degraded", True), ("Available", False), ("Progressing", True)),
            aggregation_function=any,
        )

        unhealthy_keys = set(unhealthy_operators.keys())
        if unhealthy_keys and unhealthy_keys.issubset(self.lb_operators):
            content = "Cluster has user-managed networking and only load-balancer related operators seem to be unhealthy."
            if missing := self.lb_operators - unhealthy_keys:
                content += f" Operators missing from unhealthy set: {', '.join(sorted(missing))}."
            return self.create_result(
                title="Probably user managed load-balancer issues",
                content=content,
                severity="warning",
            )

        return None
