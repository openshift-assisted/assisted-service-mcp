"""
Advanced analysis signatures for OpenShift Assisted Installer logs.
These signatures perform complex analysis across multiple log sources.
"""

import json
import logging
import re
from collections import Counter, OrderedDict
from typing import Any, Generator, Optional, Callable, cast

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


class FlappingValidations(Signature):
    """Analyzes flapping validation states."""

    validation_name_regexp = re.compile(r"Host .+: validation '(.+)'.+")
    succeed_to_failing_regexp = re.compile(
        r"Host .+: validation '.+' that used to succeed is now failing"
    )
    now_fixed_regexp = re.compile(r"Host .+: validation '.+' is now fixed")

    def analyze(self, log_analyzer) -> Optional[SignatureResult]:
        """Analyze flapping validations."""
        try:
            events_by_host = log_analyzer.get_events_by_host()

            host_tables = {}
            for host_id, events in events_by_host.items():
                succeed_to_failing_counter = Counter(
                    cast(
                        re.Match[str],
                        self.validation_name_regexp.match(event["message"]),
                    ).groups()[0]
                    for event in events
                    if self.succeed_to_failing_regexp.match(event["message"])
                )

                now_fixed = Counter(
                    cast(
                        re.Match[str],
                        self.validation_name_regexp.match(event["message"]),
                    ).groups()[0]
                    for event in events
                    if self.now_fixed_regexp.match(event["message"])
                )

                table = [
                    OrderedDict[str, Any](
                        validation=validation_name,
                        failed=f"This went from succeeding to failing {succeed_to_failing_occurrences} times",
                        fixed=f"This validation was fixed {now_fixed.get(validation_name, 0)} times",
                    )
                    for validation_name, succeed_to_failing_occurrences in succeed_to_failing_counter.items()
                ]

                if table:
                    host_tables[host_id] = self.generate_table(table)

            if host_tables:
                content = "\n".join(
                    f"Host ID {host_id}:\n{table}"
                    for host_id, table in host_tables.items()
                )

                return SignatureResult(
                    signature_name=self.name,
                    title="Flapping Validations",
                    content=content,
                    severity="warning",
                )

        except Exception as e:
            logger.error("Error in FlappingValidations: %s", e)

        return None


class NodeStatus(Signature):
    """Dump node statuses from installer gather nodes.json."""

    def analyze(self, log_analyzer) -> Optional[SignatureResult]:
        for base in (NEW_LOG_BUNDLE_PATH, OLD_LOG_BUNDLE_PATH):
            path = f"{base}/resources/nodes.json"
            try:
                nodes_json = log_analyzer.logs_archive.get(path)
            except FileNotFoundError:
                continue
            try:
                nodes = json.loads(nodes_json)
            except json.JSONDecodeError:
                continue
            nodes_table = []
            for node in nodes.get("items", []):

                def get_by_type(t, node):
                    conds = node.get("status", {}).get("conditions", [])

                    c = next((c for c in conds if c.get("type") == t), None)
                    if not c:
                        return "(Condition not found)"
                    return f"Status {c['status']} with reason {c['reason']}, message {c['message']}"

                nodes_table.append(
                    OrderedDict(
                        name=node.get("metadata", {}).get("name"),
                        MemoryPressure=get_by_type("MemoryPressure", node),
                        DiskPressure=get_by_type("DiskPressure", node),
                        PIDPressure=get_by_type("PIDPressure", node),
                        Ready=get_by_type("Ready", node),
                    )
                )
            if nodes_table:
                return SignatureResult(
                    signature_name=self.name,
                    title="Collected nodes.json from installer gather",
                    content=self.generate_table(nodes_table),
                    severity="info",
                )
            return SignatureResult(
                signature_name=self.name,
                title="Collected nodes.json from installer gather",
                content=(
                    "The nodes.json file doesn't have any node resources in it. You should probably check the kubelet logs for the 2 non-bootstrap control-plane hosts"
                ),
                severity="warning",
            )
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
