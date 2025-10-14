"""
Performance analysis signatures for OpenShift Assisted Installer logs.
These signatures analyze installation performance and identify bottlenecks.
"""

import logging
import re
from collections import OrderedDict
from typing import Optional, List, Dict, Any

import dateutil.parser

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


class OSInstallationTimeSignature(Signature):
    """Analyzes OS installation time duration."""

    writing_image_start_event_regex = re.compile(
        r".*reached installation stage Writing image to disk$"
    )
    writing_image_end_event_regex = re.compile(
        r".*reached installation stage Writing image to disk: 100%$"
    )
    slow_threshold_seconds = 300

    class NoEventFound(Exception):
        pass

    def analyze(self, log_analyzer) -> Optional[SignatureResult]:
        """Analyze OS installation time."""
        try:
            metadata = log_analyzer.metadata
            cluster = metadata["cluster"]
            events_by_host = log_analyzer.get_events_by_host()

            host_entries = []
            for host in cluster["hosts"]:
                host_id = host["id"]
                host_events = events_by_host.get(host_id, [])
                entry = self._create_host_entry(host, host_events, log_analyzer)
                host_entries.append(entry)

            # Only report if we have at least one slow host
            if any("slow" in str(host.get("duration", "")) for host in host_entries):
                content = "Some hosts had a slow OS installation. This is usually due to slow installation media (e.g. virtual media), but it could also be because of a slow disk\n\n"
                content += self.generate_table(host_entries)

                return SignatureResult(
                    signature_name=self.name,
                    title="OS Installation Time Analysis",
                    content=content,
                    severity="warning",
                )

        except Exception as e:
            logger.error("Error in OSInstallationTimeSignature: %s", e)

        return None

    @classmethod
    def _create_host_entry(
        cls, host: Dict[str, Any], host_events: List[Dict[str, Any]], log_analyzer
    ) -> Dict[str, Any]:
        """Create host entry with duration analysis."""
        entry = OrderedDict(
            id=host["id"],
            hostname=log_analyzer.get_hostname(host),
            duration="OS installation time duration could not be determined for this host",
            installation_disk=host.get("installation_disk_path", ""),
        )

        try:
            start_time = cls._get_start_event_timestamp(host_events)
            end_time = cls._get_end_event_timestamp(host_events)
            total_duration_seconds = (end_time - start_time).total_seconds()
        except cls.NoEventFound:
            return entry

        if total_duration_seconds <= 0:
            return entry

        if total_duration_seconds > cls.slow_threshold_seconds:
            entry["duration"] = (
                f"OS installation was rather slow, it took {total_duration_seconds} seconds"
            )
        else:
            entry["duration"] = (
                f"OS installation was relatively okay, it took {total_duration_seconds} seconds"
            )

        return entry

    @classmethod
    def _get_start_event_timestamp(cls, all_events: List[Dict[str, Any]]):
        """Get start event timestamp."""
        return cls._get_event_timestamp(
            cls._get_last_event(all_events, cls.writing_image_start_event_regex)
        )

    @classmethod
    def _get_end_event_timestamp(cls, all_events: List[Dict[str, Any]]):
        """Get end event timestamp."""
        return cls._get_event_timestamp(
            cls._get_last_event(all_events, cls.writing_image_end_event_regex)
        )

    @classmethod
    def _get_last_event(cls, all_events: List[Dict[str, Any]], regex):
        """Get the last event matching a regex."""
        try:
            *_, last = (
                event
                for event in all_events
                if regex.match(event["message"]) is not None
            )
        except ValueError as exc:
            raise cls.NoEventFound from exc
        return last

    @staticmethod
    def _get_event_timestamp(event: Dict[str, Any]):
        """Get timestamp from event."""
        return dateutil.parser.isoparse(event["event_time"])


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
