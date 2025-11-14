"""
ComponentsVersionSignature for OpenShift Assisted Installer logs.
"""

import logging
from typing import Optional

from .base import Signature, SignatureResult

logger = logging.getLogger(__name__)


class ComponentsVersionSignature(Signature):
    """Analyzes component versions."""

    def analyze(self, log_analyzer) -> Optional[SignatureResult]:
        """Analyze component versions."""
        try:
            metadata = log_analyzer.metadata

            content_lines = []

            release_tag = metadata.get("release_tag")
            if release_tag:
                content_lines.append(f"Release tag: {release_tag}")

            versions = metadata.get("versions")
            if versions:
                if "assisted-installer" in versions:
                    content_lines.append(
                        f"assisted-installer: {versions['assisted-installer']}"
                    )
                if "assisted-installer-controller" in versions:
                    content_lines.append(
                        f"assisted-installer-controller: {versions['assisted-installer-controller']}"
                    )
                if "discovery-agent" in versions:
                    content_lines.append(
                        f"assisted-installer-agent: {versions['discovery-agent']}"
                    )

            if content_lines:
                return SignatureResult(
                    signature_name=self.name,
                    title="Component Version Information",
                    content="\n".join(content_lines),
                    severity="info",
                )

        except Exception as e:
            logger.error("Error in ComponentsVersionSignature: %s", e)

        return None
