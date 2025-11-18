"""
ControllerWarnings signature for OpenShift Assisted Installer logs.
"""

import logging
import re
from typing import Optional

from .base import Signature, SignatureResult

logger = logging.getLogger(__name__)


class ControllerWarnings(Signature):
    """Search for warnings in controller logs."""

    def analyze(self, log_analyzer) -> Optional[SignatureResult]:
        try:
            controller_logs = log_analyzer.get_controller_logs()
        except FileNotFoundError:
            return None
        warnings = re.findall(r'time=".*" level=warning msg=".*', controller_logs)
        if warnings:
            shown = warnings[:10]
            content = "\n".join(shown)
            if len(warnings) > 10:
                content += (
                    f"\nThere are {len(warnings) - 10} additional warnings not shown"
                )
            return SignatureResult(
                signature_name=self.name,
                title="Controller warning logs",
                content=content,
                severity="warning",
            )
        return None
