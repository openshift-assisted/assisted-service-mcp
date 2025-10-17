"""
Core log analyzer for OpenShift Assisted Installer logs.
"""

import json
import logging
from collections import defaultdict
from typing import Dict, List, Any, cast

import dateutil.parser
import nestedarchive

logger = logging.getLogger(__name__)

# Archive path constants for different log bundle formats
NEW_LOG_BUNDLE_PATH = "*_bootstrap_*.tar/*_bootstrap_*.tar.gz/logs_host_*/log-bundle-*.tar.gz/log-bundle-*"
OLD_LOG_BUNDLE_PATH = (
    "*_bootstrap_*.tar.gz/logs_host_*/log-bundle-*.tar.gz/log-bundle-*"
)


class ClusterAnalyzer:
    """Analyzer for OpenShift Assisted Installer clusters."""

    def __init__(self):
        self._metadata = None
        self._cluster_events = None

    def set_cluster_metadata(self, metadata: Dict[str, Any]):
        """Set cluster metadata for analyzer."""
        if not metadata.get("cluster"):
            # Wrap metadata in a "cluster" key to match the expected structure
            metadata = {"cluster": metadata}
        self._metadata = self._clean_metadata_json(metadata)

    def set_cluster_events(self, events: List[Dict[str, Any]]):
        """Set cluster events for analyzer."""
        self._cluster_events = events

    @property
    def metadata(self) -> Dict[str, Any] | None:
        """Get cluster metadata."""
        return self._metadata

    @property
    def cluster_events(self) -> List[Dict[str, Any]] | None:
        """Get cluster events."""
        return self._cluster_events


class LogAnalyzer:
    """Analyzer for OpenShift Assisted Installer logs."""

    _metadata: dict[str, Any] | None

    def __init__(self, logs_archive: nestedarchive.RemoteNestedArchive):
        """
        Initialize the log analyzer.

        Args:
            logs_archive: RemoteNestedArchive containing the cluster logs
        """
        self.logs_archive = logs_archive
        self._metadata = None
        self._cluster_events = None

    @property
    def metadata(self) -> Dict[str, Any] | None:
        """Get cluster metadata."""
        if self._metadata is None:
            try:
                metadata_content = self.logs_archive.get("cluster_metadata.json")
                raw_metadata = json.loads(cast(str | bytes, metadata_content))

                # The metadata file contains cluster information at the root level
                # Wrap it in a "cluster" key to match the expected structure
                wrapped_metadata = {"cluster": raw_metadata}
                self._metadata = self._clean_metadata_json(wrapped_metadata)
            except Exception as e:
                logger.error("Failed to load metadata: %s", e)
                raise
        return self._metadata

    @staticmethod
    def _clean_metadata_json(md: Dict[str, Any]) -> Dict[str, Any]:
        """Clean metadata JSON by separating deleted hosts."""
        installation_start_time = dateutil.parser.isoparse(
            md["cluster"]["install_started_at"]
        )

        def host_deleted_before_installation_started(host):
            if deleted_at := host.get("deleted_at"):
                return dateutil.parser.isoparse(deleted_at) < installation_start_time
            return False

        all_hosts = md["cluster"]["hosts"]
        md["cluster"]["deleted_hosts"] = [
            h for h in all_hosts if host_deleted_before_installation_started(h)
        ]
        md["cluster"]["hosts"] = [
            h for h in all_hosts if not host_deleted_before_installation_started(h)
        ]

        return md

    def get_last_install_cluster_events(self) -> List[Dict[str, Any]]:
        """Get the cluster installation events for the most recent attempt."""
        try:
            all_events = self.get_all_cluster_events()

            # Get the last partition (latest installation attempt)
            events = self.partition_cluster_events(all_events)[-1]
        except Exception as e:
            logger.error("Failed to load cluster events: %s", e)
            return []

        return events

    def get_all_cluster_events(self) -> List[Dict[str, Any]]:
        """Get all the cluster installation events."""
        if self._cluster_events is None:
            try:
                events_content = self.logs_archive.get("cluster_events.json")
                all_events = json.loads(cast(str | bytes, events_content))

                # Get the last partition (latest installation attempt)
                self._cluster_events = self.partition_cluster_events(all_events)[-1]
            except Exception as e:
                logger.error("Failed to load cluster events: %s", e)
                self._cluster_events = []

        return self._cluster_events

    @staticmethod
    def partition_cluster_events(
        events: List[Dict[str, Any]],
    ) -> List[List[Dict[str, Any]]]:
        """Partition events by reset events to separate installation attempts."""
        partitions = []
        current_partition = []

        for event in events:
            if event["name"] == "cluster_installation_reset":
                if current_partition:
                    partitions.append(current_partition)
                    current_partition = []
            else:
                current_partition.append(event)

        if current_partition:
            partitions.append(current_partition)

        return partitions or [[]]

    def get_events_by_host(self) -> Dict[str, List[Dict[str, Any]]]:
        """Get events grouped by host ID."""
        events_by_host = defaultdict(list)
        for event in self.get_last_install_cluster_events():
            if "host_id" in event:
                events_by_host[event["host_id"]].append(event)
        return events_by_host

    def get_host_log_file(self, host_id: str, filename: str) -> str:
        """
        Get a specific log file for a host.

        Args:
            host_id: Host UUID
            filename: Name of the log file (e.g., 'agent.logs', 'journal.logs')

        Returns:
            Content of the log file

        Raises:
            FileNotFoundError: If the log file cannot be found
        """
        hostname = "*"  # Use wildcard since hostname is not always known

        # Try new log path format first
        new_logs_path = (
            f"{hostname}.tar/{hostname}.tar.gz/logs_host_{host_id}/{filename}"
        )
        try:
            content = self.logs_archive.get(new_logs_path)
            logger.debug("Found logs under new location: %s", new_logs_path)
            return cast(str, content)
        except FileNotFoundError:
            pass

        # Fall back to old log path format
        old_logs_path = f"{hostname}.tar.gz/logs_host_{host_id}/{filename}"
        content = self.logs_archive.get(old_logs_path)
        logger.debug("Found logs under old location: %s", old_logs_path)
        return cast(str, content)

    def get_journal_log(self, host_ip: str, journal_file: str, **kwargs) -> str:
        """
        Get journal logs for a specific host.

        Args:
            host_ip: IP address of the host
            journal_file: Name of the journal file
            **kwargs: Additional arguments for the archive get method

        Returns:
            Content of the journal file

        Raises:
            FileNotFoundError: If the journal file cannot be found
        """
        new_logs_path = (
            f"{NEW_LOG_BUNDLE_PATH}/control-plane/{host_ip}/journals/{journal_file}"
        )
        try:
            content = self.logs_archive.get(new_logs_path, **kwargs)
            logger.debug("Found journal under new location: %s", new_logs_path)
            return cast(str, content)
        except FileNotFoundError:
            pass

        old_logs_path = (
            f"{OLD_LOG_BUNDLE_PATH}/control-plane/{host_ip}/journals/{journal_file}"
        )
        content = self.logs_archive.get(old_logs_path, **kwargs)
        logger.debug("Found journal under old location: %s", old_logs_path)
        return cast(str, content)

    def get_controller_logs(self) -> str:
        """Get assisted installer controller logs."""
        return cast(
            str,
            self.logs_archive.get(
                "controller_logs.tar.gz/assisted-installer-controller*.logs"
            ),
        )

    def get_must_gather(self) -> bytes:
        """Get must-gather logs."""
        return cast(
            bytes,
            self.logs_archive.get(
                "controller_logs.tar.gz/must-gather.tar.gz", mode="rb"
            ),
        )

    @staticmethod
    def get_hostname(host: Dict[str, Any]) -> str:
        """Extract hostname from host metadata."""
        hostname = host.get("requested_hostname")
        if hostname:
            return hostname

        try:
            inventory = json.loads(host["inventory"])
            return inventory["hostname"]
        except (KeyError, json.JSONDecodeError):
            return host.get("id", "unknown")
