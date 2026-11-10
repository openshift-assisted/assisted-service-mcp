"""
ControllerFailedToStart signature for OpenShift Assisted Installer logs.
"""

import json
import logging

from assisted_service_mcp.src.utils.log_analyzer.log_analyzer import (
    LOG_BUNDLE_PATH,
)

from .base import Signature, SignatureResult

logger = logging.getLogger(__name__)


class ControllerFailedToStart(Signature):
    """Looks for controller readiness in pods.json when bootstrap is 'Waiting for controller'."""

    def analyze(self, log_analyzer) -> SignatureResult | None:
        cluster = log_analyzer.metadata
        bootstrap = [h for h in cluster.get("hosts", []) if h.get("bootstrap")] or []
        if not bootstrap:
            return None
        if bootstrap[0]["progress"]["current_stage"] != "Waiting for controller":
            return None
        path = f"{LOG_BUNDLE_PATH}/resources/pods.json"
        try:
            pods_json = log_analyzer.logs_archive.get(path)
        except FileNotFoundError:
            return None
        try:
            pods = json.loads(pods_json)
            # Keep eager evaluation so malformed later entries preserve existing behavior.
            controller_pod = [  # noqa: RUF015
                pod
                for pod in pods.get("items", [])
                if pod.get("metadata", {}).get("namespace") == "assisted-installer"
            ][0]
        except (AttributeError, IndexError, TypeError, ValueError):
            return None
        try:
            # Keep eager evaluation so malformed later conditions preserve existing behavior.
            ready = [  # noqa: RUF015
                condition.get("status") == "True"
                for condition in controller_pod.get("status", {}).get("conditions", {})
                if condition.get("type") == "Ready"
            ][0]
        except (AttributeError, IndexError, TypeError):
            ready = False
        conditions_tbl = self.generate_table(
            controller_pod.get("status", {}).get("conditions", [])
        )
        containers_tbl = self.generate_table(
            controller_pod.get("status", {}).get("containerStatuses", [])
        )
        content = (
            f"The controller pod {'is' if ready else 'is not'} ready.\n"
            f"Conditions:\n{conditions_tbl}\n\nContainer Statuses:\n{containers_tbl}"
        )
        return SignatureResult(
            signature_name=self.name,
            title="Assisted Installer Controller failed to start",
            content=content,
            severity="warning",
        )
