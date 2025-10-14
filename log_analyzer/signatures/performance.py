"""
Performance analysis signatures for OpenShift Assisted Installer logs.
These signatures analyze installation performance and identify bottlenecks.
"""

import logging
import re
from collections import OrderedDict
from typing import Optional, List, Dict, Any


from .base import Signature, ErrorSignature, SignatureResult

logger = logging.getLogger(__name__)


class SlowImageDownloadSignature(ErrorSignature):
    """Analyzes slow image download rates."""

    image_download_regex = re.compile(
        r"Host (?P<hostname>.+?): New image status (?P<image>.+?). result:.+?; download rate: (?P<download_rate>.+?) MBps"
    )
    minimum_download_rate_mb = 10

    def analyze(self, log_analyzer) -> Optional[SignatureResult]:
        """Analyze image download speeds."""
        try:
            events = log_analyzer.get_last_install_cluster_events()
            image_info_list = self._list_image_download_info(events)

            abnormal_image_info = []
            for image_info in image_info_list:
                if float(image_info["download_rate"]) < self.minimum_download_rate_mb:
                    abnormal_image_info.append(image_info)

            if abnormal_image_info:
                content = "Detected slow image download rate (MBps):\n"
                content += self.generate_table(abnormal_image_info)

                return self.create_result(
                    title="Slow Image Download", content=content, severity="warning"
                )

        except Exception as e:
            logger.error("Error in SlowImageDownloadSignature: %s", e)

        return None

    @classmethod
    def _list_image_download_info(
        cls, events: List[Dict[str, Any]]
    ) -> List[Dict[str, str]]:
        """Extract image download information from events."""

        def get_image_download_info(event):
            match = cls.image_download_regex.match(event["message"])
            if match:
                return match.groupdict()
            return None

        return [
            info
            for event in events
            if (info := get_image_download_info(event)) is not None
        ]
