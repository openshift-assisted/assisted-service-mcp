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


class InstallationDiskFIOSignature(Signature):
    """Analyzes slow installation disks using FIO metrics."""

    fio_regex = re.compile(r"\(fdatasync duration:\s(\d+)\sms\)")

    # pylint: disable=too-many-locals
    def analyze(self, log_analyzer) -> Optional[SignatureResult]:
        """Analyze disk FIO performance."""
        try:
            cluster = log_analyzer.metadata["cluster"]

            events = log_analyzer.get_last_install_cluster_events()
            fio_events = self._get_fio_events(events)

            fio_events_by_host = {}
            for event, fio_duration in fio_events:
                host_id = event.get("host_id")
                if host_id:
                    if host_id not in fio_events_by_host:
                        fio_events_by_host[host_id] = []
                    fio_events_by_host[host_id].append((event, fio_duration))

            hosts = []
            for host in cluster["hosts"]:
                host_fio_events = fio_events_by_host.get(host["id"], [])
                if host_fio_events:
                    _events, host_fio_events_durations = zip(*host_fio_events)
                    fio_message = (
                        "Installation disk is too slow, fio durations: "
                        + ", ".join(
                            f"{duration}ms" for duration in host_fio_events_durations
                        )
                    )

                    hosts.append(
                        OrderedDict(
                            id=host["id"],
                            hostname=log_analyzer.get_hostname(host),
                            fio=fio_message,
                            installation_disk=host.get("installation_disk_path", ""),
                        )
                    )

            if hosts:
                return SignatureResult(
                    signature_name=self.name,
                    title="Host Slow Installation Disks",
                    content=self.generate_table(hosts),
                    severity="warning",
                )

        except Exception as e:
            logger.error("Error in InstallationDiskFIOSignature: %s", e)

        return None

    @classmethod
    def _get_fio_events(cls, events):
        """Extract FIO events from cluster events."""

        def get_duration(event):
            matches = cls.fio_regex.findall(event["message"])
            if len(matches) == 0:
                return None
            return int(matches[0])

        return (
            (event, get_duration(event))
            for event in events
            if get_duration(event) is not None
        )
