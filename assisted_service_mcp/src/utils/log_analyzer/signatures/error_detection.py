"""
Error detection signatures for OpenShift Assisted Installer logs.
These signatures identify specific error conditions during installation.
"""

import logging
import os
import re
from collections import OrderedDict
from typing import Optional

import yaml
from assisted_service_mcp.src.utils.log_analyzer.log_analyzer import (
    LOG_BUNDLE_PATH,
)

from .base import ErrorSignature, SignatureResult

logger = logging.getLogger(__name__)

# pylint: disable=duplicate-code


class SNOHostnameHasEtcd(ErrorSignature):
    """Looks for etcd in SNO hostname (OCPBUGS-15852)."""

    def analyze(self, log_analyzer) -> Optional[SignatureResult]:
        """Analyze SNO hostname for etcd."""
        try:
            metadata = log_analyzer.metadata
            cluster = metadata["cluster"]

            if cluster.get("high_availability_mode") != "None":
                return None

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


class ApiInvalidCertificateSignature(ErrorSignature):
    """Detect invalid SAN values on certificate for AI API from controller logs."""

    LOG_PATTERN = re.compile(
        'time=".*" level=error msg=".*x509: certificate is valid.* not .*'
    )

    def analyze(self, log_analyzer) -> Optional[SignatureResult]:
        try:
            controller_logs = log_analyzer.get_controller_logs()
        except FileNotFoundError:
            return None

        invalid_api_log_lines = self.LOG_PATTERN.findall(controller_logs)
        if invalid_api_log_lines:
            shown = invalid_api_log_lines[:5]
            more = len(invalid_api_log_lines) - len(shown)
            content = "\n".join(shown)
            if more > 0:
                content += f"\nadditional {more} similar error log lines found"
            return self.create_result(
                title="Invalid SAN values on certificate for AI API",
                content=content,
                severity="error",
            )
        return None


class ApiExpiredCertificateSignature(ErrorSignature):
    """Detect expired or not yet valid certificate in kube-apiserver logs."""

    LOG_PATTERN = re.compile("x509: certificate has expired or is not yet valid.*")

    def analyze(self, log_analyzer) -> Optional[SignatureResult]:
        path = f"{LOG_BUNDLE_PATH}/bootstrap/containers/bootstrap-control-plane/kube-apiserver.log"
        try:
            logs = log_analyzer.logs_archive.get(path)
        except FileNotFoundError:
            return None
        invalid_api_log_lines = self.LOG_PATTERN.findall(logs)
        if invalid_api_log_lines:
            content = invalid_api_log_lines[0]
            if (num_lines := len(invalid_api_log_lines)) > 1:
                content += f"\nadditional {num_lines - 1} similar error log lines found"
            return self.create_result(
                title="Expired Certificate",
                content=content,
                severity="error",
            )
        return None


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


class MissingMC(ErrorSignature):
    """Looks for missing MachineConfig error in SNO clusters."""

    def analyze(self, log_analyzer) -> Optional[SignatureResult]:
        cluster = log_analyzer.metadata.get("cluster", {})
        if cluster.get("high_availability_mode") != "None":
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
