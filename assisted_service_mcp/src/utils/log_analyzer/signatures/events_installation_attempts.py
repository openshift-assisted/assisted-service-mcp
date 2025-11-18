"""
EventsInstallationAttempts signature for OpenShift Assisted Installer logs.
"""

import logging
from typing import Optional

from .base import Signature, SignatureResult

logger = logging.getLogger(__name__)


class EventsInstallationAttempts(Signature):
    """Inspects events file to check for multiple installation attempts."""

    def analyze(self, log_analyzer) -> Optional[SignatureResult]:
        """Analyze multiple installation attempts."""
        try:
            # Get all cluster events and partition them by reset events
            all_events = log_analyzer.get_all_cluster_events()
            partitions = log_analyzer.partition_cluster_events(all_events)
            installation_attempts = len(partitions)

            if installation_attempts != 1:
                current_events = log_analyzer.get_last_install_cluster_events()
                if current_events:
                    last_attempt_first_event = current_events[0]
                    content = (
                        f"The events file for this cluster contains events from {installation_attempts} installation attempts.\n"
                        f"When reading the events for this ticket, make sure you look only at the events for the last installation attempt,\n"
                        f"the first event in that attempt happened around {last_attempt_first_event['event_time']}."
                    )

                    return SignatureResult(
                        signature_name=self.name,
                        title="Multiple Installation Attempts in Events File",
                        content=content,
                        severity="warning",
                    )

        except Exception as e:
            logger.error("Error in EventsInstallationAttempts: %s", e)

        return None
