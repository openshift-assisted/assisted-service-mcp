"""
Advanced analysis signatures for OpenShift Assisted Installer logs.
These signatures perform complex analysis across multiple log sources.
"""

import json
import logging
import os
import re
from typing import Any, Generator, Optional, Callable, List, Dict

from log_analyzer.log_analyzer import NEW_LOG_BUNDLE_PATH, OLD_LOG_BUNDLE_PATH

from .base import Signature, SignatureResult


def operator_statuses_from_controller_logs(
    controller_log: str, include_empty: bool = False
):
    operator_regex = re.compile(r"Operator ([a-z\-]+), statuses: \[(.*)\].*")
    conditions_regex = re.compile(r"\{(.+?)\}")
    condition_regex = re.compile(
        r"([A-Za-z]+) (False|True) ([0-9a-zA-Z\-]+ [0-9a-zA-Z\:]+ [0-9a-zA-Z\-\+]+ [A-Z]+) (.*)"
    )
    operator_statuses = {}

    for operator_name, operator_status in operator_regex.findall(controller_log):
        if include_empty:
            operator_statuses[operator_name] = {}
        operator_conditions = operator_statuses.setdefault(operator_name, {})
        for operator_conditions_raw in conditions_regex.findall(operator_status):
            for (
                condition_name,
                condition_result,
                condition_timestamp,
                condition_reason,
            ) in condition_regex.findall(operator_conditions_raw):
                operator_conditions[condition_name] = {
                    "result": condition_result == "True",
                    "timestamp": condition_timestamp,
                    "reason": condition_reason,
                }

    return operator_statuses


def condition_has_result(
    operator_conditions, expected_condition_name: str, expected_condition_result: bool
) -> bool:
    return any(
        condition_values["result"] == expected_condition_result
        for condition_name, condition_values in operator_conditions.items()
        if condition_name == expected_condition_name
    )


def filter_operators(
    operator_statuses,
    required_conditions,
    aggregation_function: Callable[[Generator[Any, None, None]], bool],
):
    return {
        operator_name: operator_conditions
        for operator_name, operator_conditions in operator_statuses.items()
        if aggregation_function(
            condition_has_result(
                operator_conditions, required_condition_name, expected_condition_result
            )
            for required_condition_name, expected_condition_result in required_conditions
        )
    }


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


class UserHasLoggedIntoCluster(Signature):
    """Detect user login to cluster nodes during installation."""

    USER_LOGIN_PATTERN = re.compile(
        r"pam_unix\((sshd|login):session\): session opened for user .+ by"
    )

    def analyze(self, log_analyzer) -> Optional[SignatureResult]:
        cluster = log_analyzer.metadata.get("cluster", {})
        msgs = []
        for host in cluster.get("hosts", []):
            host_id = host["id"]
            try:
                journal_logs = log_analyzer.get_host_log_file(host_id, "journal.logs")
            except FileNotFoundError:
                continue
            if self.USER_LOGIN_PATTERN.findall(journal_logs):
                msgs.append(
                    f"Host {host_id}: found evidence of a user login during installation. This might indicate that some settings have been changed manually; if incorrect they could contribute to failure."
                )
        if msgs:
            return SignatureResult(
                signature_name=self.name,
                title="User has logged into cluster nodes during installation",
                content="\n".join(msgs),
                severity="warning",
            )
        return None


class FailedRequestTriggersHostTimeout(Signature):
    """Look for failed requests that could have caused host timeout."""

    LOG_PATTERN = re.compile(
        r'time="(?P<time>.+)" level=(?P<severity>[a-z]+) msg="(?P<message>.*api\.openshift\.com/api/assisted-install.*Service Unavailable)" file=.+'
    )
    HOST_TIMED_OUT_STATUS_INFO = (
        "Host failed to install due to timeout while connecting to host"
    )

    def analyze(self, log_analyzer) -> Optional[SignatureResult]:
        cluster = log_analyzer.metadata.get("cluster", {})
        failed_requests_hosts = set()
        timed_out_hosts = {
            h["id"]
            for h in cluster.get("hosts", [])
            if h.get("status_info") == self.HOST_TIMED_OUT_STATUS_INFO
        }
        for host in cluster.get("hosts", []):
            try:
                agent_logs = log_analyzer.get_host_log_file(host["id"], "agent.logs")
            except FileNotFoundError:
                continue
            if len(self.LOG_PATTERN.findall(agent_logs)) > 0:
                failed_requests_hosts.add(host["id"])
        intersect = failed_requests_hosts & timed_out_hosts
        if intersect:
            content = "\n".join(
                f"Host {host_id} has request failures and timed out. Did the request cause the host to timeout?"
                for host_id in sorted(intersect)
            )
            return SignatureResult(
                signature_name=self.name,
                title="Failed request triggering host timeout",
                content=content,
                severity="warning",
            )
        if failed_requests_hosts and timed_out_hosts:
            return SignatureResult(
                signature_name=self.name,
                title="Failed request triggering host timeout",
                content=(
                    f"Cluster has at least one host that failed requests ({', '.join(sorted(failed_requests_hosts))}) and at least one host that timed out ({', '.join(sorted(timed_out_hosts))})"
                ),
                severity="warning",
            )
        return None


class ControllerFailedToStart(Signature):
    """Looks for controller readiness in pods.json when bootstrap is 'Waiting for controller'."""

    def analyze(self, log_analyzer) -> Optional[SignatureResult]:
        cluster = log_analyzer.metadata.get("cluster", {})
        bootstrap = [h for h in cluster.get("hosts", []) if h.get("bootstrap")] or []
        if not bootstrap:
            return None
        if bootstrap[0]["progress"]["current_stage"] != "Waiting for controller":
            return None
        for base in (NEW_LOG_BUNDLE_PATH, OLD_LOG_BUNDLE_PATH):
            path = f"{base}/resources/pods.json"
            try:
                pods_json = log_analyzer.logs_archive.get(path)
            except FileNotFoundError:
                continue
            try:
                pods = json.loads(pods_json)
                controller_pod = [
                    pod
                    for pod in pods.get("items", [])
                    if pod.get("metadata", {}).get("namespace") == "assisted-installer"
                ][0]
            except Exception:
                continue
            try:
                ready = [
                    condition.get("status") == "True"
                    for condition in controller_pod.get("status", {}).get(
                        "conditions", {}
                    )
                    if condition.get("type") == "Ready"
                ][0]
            except Exception:
                ready = False
            conditions_tbl = self.generate_table(
                controller_pod.get("status", {}).get("conditions", [])
            )
            containers_tbl = self.generate_table(
                controller_pod.get("status", {}).get("containerStatuses", [])
            )
            content = (
                f"The controller pod {'is' if ready else 'is not'} ready.\n"
                f"Conditions:\n{conditions_tbl}\n\nContainer Statuses:\n{containers_tbl}"
            )
            return SignatureResult(
                signature_name=self.name,
                title="Assisted Installer Controller failed to start",
                content=content,
                severity="warning",
            )
        return None


class MachineConfigDaemonErrorExtracting(Signature):
    """Looks for MCD firstboot extraction error (OCPBUGS-5352)."""

    mco_error = re.compile(
        r"must be empty, pass --confirm to overwrite contents of directory$",
        re.MULTILINE,
    )

    def analyze(self, log_analyzer) -> Optional[SignatureResult]:
        for base in (NEW_LOG_BUNDLE_PATH, OLD_LOG_BUNDLE_PATH):
            path = (
                f"{base}/control-plane/*/journals/machine-config-daemon-firstboot.log"
            )
            try:
                mcd_logs = log_analyzer.logs_archive.get(path)
            except FileNotFoundError:
                continue
            if self.mco_error.search(mcd_logs):
                return SignatureResult(
                    signature_name=self.name,
                    title="machine-config-daemon could not extract machine-os-content",
                    content=(
                        "machine-config-daemon-firstboot logs indicate a node may be hitting OCPBUGS-5352"
                    ),
                    severity="warning",
                )
        return None


class BootkubeAttempts(Signature):
    """Counts the number of times bootkube attempted to run."""

    def __init__(self):
        """Initialize the signature."""
        super().__init__()

    def analyze(self, log_analyzer) -> Optional[SignatureResult]:
        """Analyze bootkube attempts from bootkube.json file."""
        try:
            bootkube_json_path = f"{NEW_LOG_BUNDLE_PATH}/bootstrap/services/bootkube.json"

            try:
                bootkube_content = log_analyzer.logs_archive.get(bootkube_json_path)
            except FileNotFoundError:
                return None

            # Parse the JSON content
            try:
                bootkube_events = json.loads(bootkube_content)
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse bootkube.json: {e}")
                return None

            # Count "service start" phases to determine number of attempts
            # Deduplicate by timestamp since there can be multiple entries with the same timestamp
            service_start_timestamps = set()
            for event in bootkube_events:
                if event.get("phase") == "service start":
                    timestamp = event.get("timestamp")
                    if timestamp:
                        service_start_timestamps.add(timestamp)

            service_start_count = len(service_start_timestamps)

            if service_start_count == 0:
                return None

            # Create content with attempt details
            content = f"Bootkube attempted to run {service_start_count} time(s).\n\n"

            if service_start_count > 1:
                content += "Multiple bootkube attempts detected. This may indicate:\n"
                content += "- Previous attempts failed and bootkube was restarted\n"
                content += "- System instability during bootstrap process\n"
                content += "- Resource constraints or timing issues\n\n"
                content += "Review the bootkube.json file for detailed attempt information and failure reasons."
                severity = "warning"
            else:
                content += "Single bootkube attempt detected."
                severity = "info"

            return SignatureResult(
                signature_name=self.name,
                title="Bootkube Attempts Analysis",
                content=content,
                severity=severity
            )

        except Exception as e:
            logger.error(f"Error in BootkubeAttempts: {e}", exc_info=True)
            return None


class ContainerCrashAnalysis(Signature):
    """Analyzes container crashes in the last 30 minutes of the install from kubelet logs."""

    def __init__(self):
        """Initialize the signature."""
        super().__init__()

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
                    logger.error(f"Error analyzing host directory {host_dir}: {e}", exc_info=True)
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
            sorted_hosts = sorted(all_host_results, key=lambda x: x['total_crashes'], reverse=True)

            for host_result in sorted_hosts:
                total_crashes += host_result['total_crashes']
                content += host_result['content']

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
                severity=severity
            )

        except Exception as e:
            logger.error(f"Error in ContainerCrashAnalysis: {e}", exc_info=True)
            return None

    def _get_host_directories(self, log_analyzer) -> List[Dict[str, str]]:
        """Get list of host directories to analyze."""
        host_dirs = []

        # Add bootstrap directory
        host_dirs.append({
            'host_id': 'bootstrap',
            'kubelet_path': f"{NEW_LOG_BUNDLE_PATH}/bootstrap/journals/kubelet.log",
            'containers_path': f"{NEW_LOG_BUNDLE_PATH}/bootstrap/containers/"
        })

        # Add control-plane directories
        try:
            control_plane_dir = log_analyzer.logs_archive.get(f"{NEW_LOG_BUNDLE_PATH}/control-plane/")
            logger.debug(f"Found control-plane directory: {NEW_LOG_BUNDLE_PATH}/control-plane/")

            for node_dir in getattr(control_plane_dir, "iterdir", lambda: [])():
                node_ip = os.path.basename(node_dir)
                logger.debug(f"Found control plane node: {node_ip}")

                host_dirs.append({
                    'host_id': node_ip,
                    'kubelet_path': f"{NEW_LOG_BUNDLE_PATH}/control-plane/{node_ip}/journals/kubelet.log",
                    'containers_path': f"{NEW_LOG_BUNDLE_PATH}/control-plane/{node_ip}/containers/"
                })
        except FileNotFoundError as e:
            logger.debug(f"Control-plane directory not found: {e}")

        return host_dirs

    def _analyze_host_directory(self, log_analyzer, host_dir: Dict[str, str]) -> Optional[Dict]:
        """Analyze a single host directory for container crashes."""
        from collections import defaultdict
        from datetime import datetime, timedelta

        host_id = host_dir['host_id']
        kubelet_path = host_dir['kubelet_path']

        logger.debug(f"Analyzing host directory: {host_id}")

        try:
            kubelet_logs = log_analyzer.logs_archive.get(kubelet_path)
            logger.debug(f"Found kubelet.log for {host_id}, size: {len(kubelet_logs)} characters")
        except FileNotFoundError:
            logger.debug(f"kubelet.log not found for {host_id} at path: {kubelet_path}")
            return None

        # Process kubelet logs to find crashes and latest timestamp
        crash_entries, latest_timestamp = self._process_kubelet_logs(kubelet_logs, host_id)

        if not crash_entries:
            logger.debug(f"No crash entries found for {host_id}")
            return None

        logger.debug(f"Found {len(crash_entries)} crash entries for {host_id}, latest timestamp: {latest_timestamp}")

        # Filter crashes to last 30 minutes based on this host's latest timestamp
        filtered_crashes = []
        if latest_timestamp:
            thirty_minutes_before_latest = latest_timestamp - timedelta(minutes=30)
            logger.debug(f"Filtering crashes for {host_id} from {thirty_minutes_before_latest} to {latest_timestamp}")

            for entry in crash_entries:
                try:
                    # Parse the crash timestamp
                    crash_time = datetime.strptime(entry['timestamp_str'], "%b %d %H:%M:%S")

                    # Check if this crash is within the last 30 minutes of this host's latest log entry
                    if crash_time >= thirty_minutes_before_latest:
                        logger.debug(f"Including crash for {host_id}: {entry['container_name']} at {entry['timestamp_str']}")
                        filtered_crashes.append(entry)
                    else:
                        logger.debug(f"Excluding crash for {host_id} (too old): {entry['container_name']} at {entry['timestamp_str']}")
                except ValueError as e:
                    logger.debug(f"Failed to parse crash timestamp '{entry['timestamp_str']}' for {host_id}: {e}")
                    # If timestamp parsing fails, still count the crash
                    filtered_crashes.append(entry)
        else:
            logger.debug(f"No latest timestamp found for {host_id}, counting all crashes")
            filtered_crashes = crash_entries

        if not filtered_crashes:
            logger.debug(f"No crashes in last 30 minutes for {host_id}")
            return None

        # Count crashes by container for this host
        container_crashes = defaultdict(int)
        for entry in filtered_crashes:
            container_crashes[entry['container_name']] += 1

        total_crashes = sum(container_crashes.values())
        logger.debug(f"Total crashes for {host_id}: {total_crashes}")

        # Generate content for this host
        content = f"Host {host_id} ({total_crashes} total crashes):\n"

        # Sort containers by crash count for this host
        sorted_containers = sorted(container_crashes.items(), key=lambda x: x[1], reverse=True)

        for container_name, crash_count in sorted_containers:
            content += f"  • {container_name}: {crash_count} crash(es)\n"

            # Try to find and include the last 20 logs for this container
            try:
                container_logs_list = self._get_container_logs(log_analyzer, host_id, container_name, host_dir['containers_path'])
                if container_logs_list:
                    content += "    Last 20 container logs:\n"
                    for log_file_name, log_lines in container_logs_list:
                        if len(container_logs_list) > 1:
                            content += f"      --- {log_file_name} ---\n"
                        for log_line in log_lines:
                            content += f"      {log_line}\n"
                        if len(container_logs_list) > 1:
                            content += f"      --- end {log_file_name} ---\n"
                else:
                    content += "    (Container logs not found)\n"
            except Exception as e:
                logger.debug(f"Failed to get logs for {container_name} on {host_id}: {e}")
                content += "    (Error retrieving container logs)\n"

        content += "\n"

        return {
            'host_ip': host_id,
            'total_crashes': total_crashes,
            'content': content
        }

    def _process_kubelet_logs(self, kubelet_logs: str, node_identifier: str) -> tuple:
        """Process kubelet logs to find timestamps and crash patterns.

        Returns:
            tuple: (crash_entries, latest_timestamp)
        """
        from datetime import datetime

        # Pattern to match container crash errors in kubelet logs
        crash_pattern = re.compile(
            r'(\w{3} \d{1,2} \d{2}:\d{2}:\d{2}) .* "Error syncing pod, skipping" err="failed to \\"StartContainer\\" for \\"([^"]+)\\" with CrashLoopBackOff'
        )

        crash_entries = []
        latest_timestamp = None

        line_count = 0
        crash_matches_found = 0

        for line in kubelet_logs.split('\n'):
            line_count += 1
            if not line.strip():
                continue

            # Extract timestamp from any log line (format: "Sep 17 14:40:15")
            timestamp_match = re.match(r'^(\w{3} \d{1,2} \d{2}:\d{2}:\d{2})', line)
            if timestamp_match:
                timestamp_str = timestamp_match.group(1)
                try:
                    # Parse the timestamp (format: "Sep 17 14:40:15")
                    log_time = datetime.strptime(timestamp_str, "%b %d %H:%M:%S")

                    # Track the latest timestamp
                    if latest_timestamp is None or log_time > latest_timestamp:
                        latest_timestamp = log_time

                except ValueError as e:
                    logger.debug(f"Failed to parse timestamp '{timestamp_str}': {e}")
                    continue

            # Check for crash patterns
            crash_match = crash_pattern.search(line)
            if crash_match:
                crash_matches_found += 1
                timestamp_str = crash_match.group(1)
                container_name = crash_match.group(2)
                logger.debug(f"Found crash match: {container_name} at {timestamp_str}")
                crash_entries.append({
                    'timestamp_str': timestamp_str,
                    'container_name': container_name,
                    'node_ip': node_identifier,
                    'line': line
                })

        logger.debug(f"Node {node_identifier}: processed {line_count} lines, found {crash_matches_found} crash matches")
        return crash_entries, latest_timestamp

    def _get_container_logs(self, log_analyzer, host_ip: str, container_name: str, containers_dir_path: str) -> List[tuple]:
        """Get the last 20 lines from all container log files for a given container."""
        try:

            try:
                containers_dir = log_analyzer.logs_archive.get(containers_dir_path)
            except FileNotFoundError:
                logger.debug(f"Containers directory not found: {containers_dir_path}")
                return []

            # Find all container log files (they have a random hash component)
            # Pattern: {container_name}-{hash}.log (exact match, not substring)
            container_log_files = []
            for file in getattr(containers_dir, "iterdir", lambda: [])():
                file_path = str(file) if hasattr(file, '__str__') else file
                # Extract just the filename from the full path
                file_name = os.path.basename(file_path)
                logger.debug(f"evaluating file name {file_name} from path {file_path}")

                pattern = re.compile(rf"^{re.escape(container_name)}-[a-f0-9]{{64}}\.log$")
                if pattern.match(file_name):
                    container_log_files.append(file_name)

            if not container_log_files:
                logger.debug(f"No log files found for container {container_name} on {host_ip}")
                return []

            logger.debug(f"Found {len(container_log_files)} log files for container {container_name} on {host_ip}")

            # Process each log file
            all_logs = []
            for log_file_name in sorted(container_log_files):  # Sort for consistent ordering
                log_file_path = f"{containers_dir_path}/{log_file_name}"

                try:
                    container_log_content = log_analyzer.logs_archive.get(log_file_path)
                except FileNotFoundError:
                    logger.debug(f"Container log file not found: {log_file_path}")
                    continue

                # Get the last 20 lines from this log file
                log_lines = container_log_content.split('\n')
                # Filter out empty lines and get last 20 non-empty lines
                non_empty_lines = [line for line in log_lines if line.strip()]
                last_20_lines = non_empty_lines[-20:] if len(non_empty_lines) > 20 else non_empty_lines

                if last_20_lines:
                    all_logs.append((log_file_name, last_20_lines))
                    logger.debug(f"Retrieved {len(last_20_lines)} log lines from {log_file_name}")

            return all_logs

        except Exception as e:
            logger.debug(f"Error getting container logs for {container_name} on {host_ip}: {e}")
            return []


# Add more advanced analysis signatures here:
# - AllInstallationAttemptsSignature (requires JIRA integration)
# - MustGatherAnalysis
# - NodeStatus
# - UserManagedNetworkingLoadBalancer
# - FailedRequestTriggersHostTimeout
# - ControllerWarnings
# - UserHasLoggedIntoCluster
# - OSTreeCommitMismatch
# - ControllerFailedToStart
# - MachineConfigDaemonErrorExtracting
