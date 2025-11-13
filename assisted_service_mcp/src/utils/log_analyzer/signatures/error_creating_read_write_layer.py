"""
ErrorCreatingReadWriteLayer signature for OpenShift Assisted Installer logs.
"""

import logging
import os
from typing import Optional

import yaml

from .base import ErrorSignature, SignatureResult

logger = logging.getLogger(__name__)


class ErrorCreatingReadWriteLayer(ErrorSignature):
    """Detect pods failing with error creating read-write layer (BZ 1993243)."""

    @staticmethod
    def _is_bad_pod(pod):
        return any(
            containerStatus.get("state", {}).get("waiting", {}).get("reason")
            == "CreateContainerError"
            and "error creating read-write layer with ID"
            in containerStatus.get("state", {}).get("waiting", {}).get("message", "")
            for containerStatus in pod.get("status", {}).get("containerStatuses", [])
        )

    def analyze(self, log_analyzer) -> Optional[SignatureResult]:
        try:
            namespaces_dir = log_analyzer.logs_archive.get(
                "controller_logs.tar.gz/must-gather.tar.gz/must-gather.local.*/quay-io-openshift-release-dev-*/namespaces"
            )
        except FileNotFoundError:
            return None

        messages = []
        for namespace_dir in self.archive_dir_contents(namespaces_dir):
            try:
                pods_yaml_path = os.path.join(namespace_dir, "core", "pods.yaml")
                pods_yaml = log_analyzer.logs_archive.get(pods_yaml_path)
            except FileNotFoundError:
                continue
            try:
                pods_doc = yaml.safe_load(pods_yaml) or {}
                for pod in pods_doc.get("items", []):
                    if self._is_bad_pod(pod):
                        messages.append(
                            f"Pod {pod['metadata']['name']} in namespace {pod['metadata']['namespace']} has a container with an error creating the read-write layer, see BZ 1993243"
                        )
            except Exception:
                continue

        if messages:
            return self.create_result(
                title="Error creating read-write layer - Bugzilla 1993243",
                content="\n\n".join(messages),
                severity="error",
            )
        return None
