"""
ApiInvalidCertificateSignature for OpenShift Assisted Installer logs.
"""

import logging
import re
from typing import Optional

from .base import ErrorSignature, SignatureResult

logger = logging.getLogger(__name__)


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
