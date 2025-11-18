"""
ApiExpiredCertificateSignature for OpenShift Assisted Installer logs.
"""

import logging
import re
from typing import Optional

from assisted_service_mcp.src.utils.log_analyzer.log_analyzer import (
    LOG_BUNDLE_PATH,
)

from .base import ErrorSignature, SignatureResult

logger = logging.getLogger(__name__)


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
