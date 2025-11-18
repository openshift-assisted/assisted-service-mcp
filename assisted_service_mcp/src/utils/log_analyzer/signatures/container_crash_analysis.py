"""
ContainerCrashAnalysis signature for OpenShift Assisted Installer logs.
"""

import logging
import os
import re
from collections import defaultdict
from datetime import datetime, timedelta
from operator import itemgetter
from typing import Optional, List, Dict

from assisted_service_mcp.src.utils.log_analyzer.log_analyzer import (
    LOG_BUNDLE_PATH,
)

from .base import Signature, SignatureResult

logger = logging.getLogger(__name__)


class ContainerCrashAnalysis(Signature):
    """Analyzes container crashes in the last 30 minutes of the install from kubelet logs."""

    def analyze(self, log_analyzer) -> Optional[SignatureResult]:
        """Analyze container crashes from kubelet logs in control plane nodes."""
        try:
            logger.debug("Starting ContainerCrashAnalysis")

            # Collect results from all hosts
            all_host_results = []

            for host_dir in self._get_host_directories(log_analyzer):
                try:
                    host_result = self._analyze_host_directory(log_analyzer, host_dir)
                    if host_result:
                        all_host_results.append(host_result)
                except Exception as e:
                    logger.error(
                        "Error analyzing host directory %s: %s",
                        host_dir,
                        e,
                        exc_info=True,
                    )
                    # Continue with other hosts even if one fails
                    continue

            # If no crashes found across any host, return None
            if not all_host_results:
                logger.debug("No container crashes found on any host, returning None")
                return None

            # Combine results from all hosts
            content = "Container crashes detected in the last 30 minutes:\n\n"
            total_crashes = 0

            # Sort hosts by total crash count (descending)
            sorted_hosts = sorted(
                all_host_results, key=lambda x: x["total_crashes"], reverse=True
            )

            for host_result in sorted_hosts:
                total_crashes += host_result["total_crashes"]
                content += host_result["content"]

            # Determine severity based on total crash count across all hosts
            if total_crashes >= 10:
                severity = "error"
            elif total_crashes >= 5:
                severity = "warning"
            else:
                severity = "info"

            return SignatureResult(
                signature_name=self.name,
                title="Container Crash Analysis (Last 30 Minutes)",
                content=content,
                severity=severity,
            )

        except Exception as e:
            logger.error("Error in ContainerCrashAnalysis: %s", e, exc_info=True)
            return None

    def _get_host_directories(self, log_analyzer) -> List[Dict[str, str]]:
        """Get list of host directories to analyze."""
        host_dirs = []

        # Add bootstrap directory
        host_dirs.append(
            {
                "host_id": "bootstrap",
                "kubelet_path": f"{LOG_BUNDLE_PATH}/bootstrap/journals/kubelet.log",
                "containers_path": f"{LOG_BUNDLE_PATH}/bootstrap/containers/",
            }
        )

        # Add control-plane directories
        try:
            control_plane_dir = log_analyzer.logs_archive.get(
                f"{LOG_BUNDLE_PATH}/control-plane/"
            )
            logger.debug(
                "Found control-plane directory: %s/control-plane/", LOG_BUNDLE_PATH
            )

            for node_dir in self.archive_dir_contents(control_plane_dir):
                node_ip = node_dir.name
                logger.debug("Found control plane node: %s", node_ip)

                host_dirs.append(
                    {
                        "host_id": node_ip,
                        "kubelet_path": f"{LOG_BUNDLE_PATH}/control-plane/{node_ip}/journals/kubelet.log",
                        "containers_path": f"{LOG_BUNDLE_PATH}/control-plane/{node_ip}/containers/",
                    }
                )
        except FileNotFoundError as e:
            logger.debug("Control-plane directory not found: %s", e)

        return host_dirs

    def _analyze_host_directory(
        self, log_analyzer, host_dir: Dict[str, str]
    ) -> Optional[Dict]:
        """Analyze a single host directory for container crashes."""
        host_id = host_dir["host_id"]
        logger.debug("Analyzing host directory: %s", host_id)

        # Get kubelet logs
        kubelet_path = host_dir["kubelet_path"]
        try:
            kubelet_logs = log_analyzer.logs_archive.get(kubelet_path)
            logger.debug(
                "Found kubelet.log for %s, size: %d characters",
                host_id,
                len(kubelet_logs),
            )
        except FileNotFoundError:
            logger.debug(
                "kubelet.log not found for %s at path: %s", host_id, kubelet_path
            )
            return None

        # Process crashes
        crash_entries, latest_timestamp = self._find_crashes_in_kubelet_logs(
            kubelet_logs, host_id
        )
        if not crash_entries:
            logger.debug("No crash entries found for %s", host_id)
            return None

        # Filter crashes to last 30 minutes
        filtered_crashes = self._filter_crashes_by_time(
            crash_entries, latest_timestamp, host_id
        )
        if not filtered_crashes:
            logger.debug("No crashes in last 30 minutes for %s", host_id)
            return None

        # Generate result
        return self._generate_host_result(log_analyzer, host_dir, filtered_crashes)

    def _filter_crashes_by_time(
        self,
        crash_entries: List[Dict],
        latest_timestamp: Optional[datetime],
        host_id: str,
    ) -> List[Dict]:
        """Filter crashes to last 30 minutes based on latest timestamp."""
        if not latest_timestamp:
            logger.debug(
                "No latest timestamp found for %s, counting all crashes", host_id
            )
            return crash_entries

        thirty_minutes_before_latest = latest_timestamp - timedelta(minutes=30)
        logger.debug(
            "Filtering crashes for %s from %s to %s",
            host_id,
            thirty_minutes_before_latest,
            latest_timestamp,
        )

        filtered_crashes = []
        for entry in crash_entries:
            try:
                # Parse timestamp with current year to avoid deprecation warning
                crash_time = datetime.strptime(
                    f"{entry['timestamp_str']} {datetime.now().year}",
                    "%b %d %H:%M:%S %Y",
                )
            except ValueError as e:
                logger.debug(
                    "Failed to parse crash timestamp '%s' for %s: %s",
                    entry["timestamp_str"],
                    host_id,
                    e,
                )
                continue

            if crash_time >= thirty_minutes_before_latest:
                filtered_crashes.append(entry)

        return filtered_crashes

    def _generate_host_result(
        self, log_analyzer, host_dir: Dict[str, str], filtered_crashes: List[Dict]
    ) -> Dict:
        """Generate the result dictionary for a host."""
        host_id = host_dir["host_id"]

        # Count crashes by container
        container_crashes = defaultdict(int)
        for entry in filtered_crashes:
            container_crashes[entry["container_name"]] += 1

        total_crashes = sum(container_crashes.values())
        logger.debug("Total crashes for %s: %d", host_id, total_crashes)

        # Generate content
        content = f"Host {host_id} ({total_crashes} total crashes):\n"
        content += self._generate_container_content(
            log_analyzer, host_dir, container_crashes
        )
        content += "\n"

        return {"total_crashes": total_crashes, "content": content}

    def _generate_container_content(
        self, log_analyzer, host_dir: Dict[str, str], container_crashes: Dict
    ) -> str:
        """Generate content for container crashes."""
        host_id = host_dir["host_id"]
        content = ""

        # Sort containers by crash count
        sorted_containers = sorted(
            container_crashes.items(), key=itemgetter(1), reverse=True
        )

        for container_name, crash_count in sorted_containers:
            content += f"  • {container_name}: {crash_count} crash(es)\n"
            content += self._get_container_logs_content(
                log_analyzer, host_id, container_name, host_dir["containers_path"]
            )

        return content

    def _get_container_logs_content(
        self, log_analyzer, host_id: str, container_name: str, containers_path: str
    ) -> str:
        """Get formatted container logs content."""
        try:
            container_logs_list = self._get_container_logs(
                log_analyzer, host_id, container_name, containers_path
            )
            if container_logs_list:
                content = "    Last 20 container logs:\n"
                for log_file_name, log_lines in container_logs_list:
                    if len(container_logs_list) > 1:
                        content += f"      --- {log_file_name} ---\n"
                    for log_line in log_lines:
                        content += f"      {log_line}\n"
                    if len(container_logs_list) > 1:
                        content += f"      --- end {log_file_name} ---\n"
                return content

            return "    (Container logs not found)\n"
        except Exception as e:
            logger.debug(
                "Failed to get logs for %s on %s: %s", container_name, host_id, e
            )
            return "    (Error retrieving container logs)\n"

    def _find_crashes_in_kubelet_logs(
        self, kubelet_logs: str, node_identifier: str
    ) -> tuple:
        """Process kubelet logs to find timestamps and crash patterns.

        Returns:
            tuple: (crash_entries, latest_timestamp)
        """
        # Pattern to match container crash errors in kubelet logs
        crash_pattern = re.compile(
            r'(\w{3} \d{1,2} \d{2}:\d{2}:\d{2}) .* "Error syncing pod, skipping" err="failed to \\"StartContainer\\" for \\"([^"]+)\\" with CrashLoopBackOff'
        )

        crash_entries = []
        latest_timestamp = None
        for line in kubelet_logs.split("\n"):
            if not line.strip():
                continue

            # Extract timestamp from any log line (format: "Sep 17 14:40:15")
            timestamp_match = re.match(r"^(\w{3} \d{1,2} \d{2}:\d{2}:\d{2})", line)
            if timestamp_match:
                timestamp_str = timestamp_match.group(1)
                try:
                    # Parse timestamp with current year to avoid deprecation warning
                    log_time = datetime.strptime(
                        f"{timestamp_str} {datetime.now().year}", "%b %d %H:%M:%S %Y"
                    )
                except ValueError as e:
                    logger.warning(
                        "Failed to parse timestamp '%s': %s", timestamp_str, e
                    )
                    continue

                # Track the latest timestamp
                if latest_timestamp is None or log_time > latest_timestamp:
                    latest_timestamp = log_time

            # Check for crash patterns
            crash_match = crash_pattern.search(line)
            if crash_match:
                timestamp_str = crash_match.group(1)
                container_name = crash_match.group(2)
                logger.debug(
                    "Found crash match: %s at %s", container_name, timestamp_str
                )
                crash_entries.append(
                    {
                        "timestamp_str": timestamp_str,
                        "container_name": container_name,
                        "node_ip": node_identifier,
                        "line": line,
                    }
                )

        logger.debug(
            "Node %s: found %d crash matches",
            node_identifier,
            len(crash_entries),
        )
        return crash_entries, latest_timestamp

    def _get_container_logs(
        self, log_analyzer, host_ip: str, container_name: str, containers_dir_path: str
    ) -> List[tuple]:
        """Get the last 20 lines from all container log files for a given container."""
        try:
            containers_dir = log_analyzer.logs_archive.get(containers_dir_path)
        except FileNotFoundError:
            logger.debug("Containers directory not found: %s", containers_dir_path)
            return []

        container_log_files = self._find_container_log_files(
            containers_dir, container_name, host_ip
        )
        if not container_log_files:
            return []

        return self._process_container_log_files(
            log_analyzer, container_log_files, containers_dir_path
        )

    def _find_container_log_files(
        self, containers_dir, container_name: str, host_ip: str
    ) -> List[str]:
        """Find all container log files for a given container."""
        container_log_files = []
        pattern = re.compile(rf"^{re.escape(container_name)}-[a-f0-9]{{64}}\.log$")

        for file in self.archive_dir_contents(containers_dir):
            logger.debug("evaluating file name %s from path %s", file.name, file)

            if pattern.match(file.name):
                container_log_files.append(file.name)

        if not container_log_files:
            logger.debug(
                "No log files found for container %s on %s", container_name, host_ip
            )
        else:
            logger.debug(
                "Found %d log files for container %s on %s",
                len(container_log_files),
                container_name,
                host_ip,
            )

        return container_log_files

    def _process_container_log_files(
        self, log_analyzer, container_log_files: List[str], containers_dir_path: str
    ) -> List[tuple]:
        """Process container log files and extract last 20 lines."""
        all_logs = []

        for log_file_name in sorted(container_log_files):
            log_file_path = os.path.join(containers_dir_path, log_file_name)

            try:
                container_log_content = log_analyzer.logs_archive.get(log_file_path)
            except FileNotFoundError:
                logger.debug("Container log file not found: %s", log_file_path)
                continue

            last_20_lines = self._extract_last_lines(container_log_content)
            if last_20_lines:
                all_logs.append((log_file_name, last_20_lines))
                logger.debug(
                    "Retrieved %d log lines from %s",
                    len(last_20_lines),
                    log_file_name,
                )

        return all_logs

    def _extract_last_lines(self, log_content: str, max_lines: int = 20) -> List[str]:
        """Extract the last N non-empty lines from log content."""
        log_lines = log_content.split("\n")
        non_empty_lines = [line for line in log_lines if line.strip()]
        return (
            non_empty_lines[-max_lines:]
            if len(non_empty_lines) > max_lines
            else non_empty_lines
        )
