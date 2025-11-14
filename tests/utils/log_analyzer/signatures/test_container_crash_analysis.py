"""
Unit tests for ContainerCrashAnalysis signature.
"""

from pathlib import Path
from typing import Mapping
from unittest.mock import MagicMock

from assisted_service_mcp.src.utils.log_analyzer.log_analyzer import (
    LogAnalyzer,
    LOG_BUNDLE_PATH,
)
from assisted_service_mcp.src.utils.log_analyzer.signatures.container_crash_analysis import (
    ContainerCrashAnalysis,
)
from assisted_service_mcp.src.utils.log_analyzer.signatures.base import SignatureResult


def make_archive(get_map: Mapping[str, object]) -> object:
    """Create a fake archive with a .get(path) API from a mapping."""

    class _Archive:
        def get(self, path: str, **_kwargs: str) -> object:
            if path in get_map:
                return get_map[path]
            raise FileNotFoundError(path)

    return _Archive()


class TestContainerCrashAnalysis:
    """Test cases for ContainerCrashAnalysis signature."""

    def _create_kubelet_log_with_crashes(
        self, crashes_data: list[dict[str, str]]
    ) -> str:
        """Helper to create kubelet log content with crash entries."""

        log_lines = [
            "Sep 17 14:30:00 k8s-masters1 kubenswrapper[2575]: I0917 14:30:00.123456 2575 kubelet.go:123] Starting kubelet",
            "Sep 17 14:31:00 k8s-masters1 kubenswrapper[2575]: I0917 14:31:00.123456 2575 kubelet.go:456] Normal operation",
        ]

        for crash in crashes_data:
            timestamp = crash.get("timestamp", "Sep 17 14:35:00")
            container = crash.get("container", "test-container")
            pod_name = f"{container}-k8s-masters1"
            namespace = "openshift-system"
            pod_uid = "5caccf7ea3d504f6eba4b8ea6c6ed537"

            log_lines.append(
                f"{timestamp} k8s-masters1 kubenswrapper[2575]: E0917 14:35:00.402290 2575 pod_workers.go:1301] "
                f'"Error syncing pod, skipping" err="failed to \\"StartContainer\\" for \\"{container}\\" with '
                f'CrashLoopBackOff: \\"back-off 10s restarting failed container={container} pod={pod_name}_{namespace}'
                f'({pod_uid})\\"" pod="{namespace}/{pod_name}" podUID="{pod_uid}"'
            )

        log_lines.append(
            "Sep 17 14:40:00 k8s-masters1 kubenswrapper[2575]: I0917 14:40:00.123456 2575 kubelet.go:789] Latest log entry"
        )

        return "\n".join(log_lines)

    def _create_container_log_content(
        self, container_name: str, lines_count: int = 20
    ) -> str:
        """Helper to create container log content."""

        log_lines = []
        for i in range(lines_count):
            log_lines.append(
                f"2024-09-17T14:35:00.123456789Z Container {container_name} log line {i+1}"
            )
        return "\n".join(log_lines)

    def _create_mock_directory(self, files: list[str]) -> object:
        """Helper to create a mock directory with files."""

        mock_dir = MagicMock()
        mock_files = []
        for filename in files:
            mock_file = Path(f"/some/extracted/path/{filename}")
            mock_files.append(mock_file)
        mock_dir.iterdir.return_value = mock_files
        return mock_dir

    def test_no_crashes_found(self) -> None:
        """Test ContainerCrashAnalysis when no crashes are found."""
        signature = ContainerCrashAnalysis()

        # Create kubelet log without crashes
        kubelet_log = self._create_kubelet_log_with_crashes([])

        archive = make_archive(
            {
                f"{LOG_BUNDLE_PATH}/bootstrap/journals/kubelet.log": kubelet_log,
            }
        )

        log_analyzer = LogAnalyzer(archive)
        result = signature.analyze(log_analyzer)

        assert result is None

    def test_single_container_crash_info_severity(self) -> None:
        """Test ContainerCrashAnalysis with single crash (info severity)."""
        signature = ContainerCrashAnalysis()

        # Create kubelet log with one crash
        crashes = [{"timestamp": "Sep 17 14:35:00", "container": "etcd"}]
        kubelet_log = self._create_kubelet_log_with_crashes(crashes)
        log_file_name = (
            "etcd-abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890.log"
        )

        archive_map = {
            f"{LOG_BUNDLE_PATH}/bootstrap/journals/kubelet.log": kubelet_log,
            f"{LOG_BUNDLE_PATH}/bootstrap/containers/": self._create_mock_directory(
                [log_file_name]
            ),
            f"{LOG_BUNDLE_PATH}/bootstrap/containers/{log_file_name}": self._create_container_log_content(
                "etcd"
            ),
        }

        archive = make_archive(archive_map)
        log_analyzer = LogAnalyzer(archive)
        result = signature.analyze(log_analyzer)

        assert result is not None
        assert isinstance(result, SignatureResult)
        assert result.signature_name == "ContainerCrashAnalysis"
        assert result.title == "Container Crash Analysis (Last 30 Minutes)"
        assert result.severity == "info"
        assert "Container crashes detected in the last 30 minutes" in result.content
        assert "Host bootstrap (1 total crashes)" in result.content
        assert "etcd: 1 crash(es)" in result.content
        assert "Container etcd log line" in result.content

    def test_multiple_crashes_warning_severity(self) -> None:
        """Test ContainerCrashAnalysis with multiple crashes (warning severity)."""
        signature = ContainerCrashAnalysis()

        # Create kubelet log with 6 crashes (should trigger warning)
        crashes = [
            {"timestamp": "Sep 17 14:35:00", "container": "etcd"},
            {"timestamp": "Sep 17 14:36:00", "container": "etcd"},
            {"timestamp": "Sep 17 14:37:00", "container": "kube-apiserver"},
            {"timestamp": "Sep 17 14:38:00", "container": "kube-apiserver"},
            {"timestamp": "Sep 17 14:39:00", "container": "kube-controller-manager"},
            {"timestamp": "Sep 17 14:39:30", "container": "kube-scheduler"},
        ]
        kubelet_log = self._create_kubelet_log_with_crashes(crashes)

        archive_map = {
            f"{LOG_BUNDLE_PATH}/bootstrap/journals/kubelet.log": kubelet_log,
            f"{LOG_BUNDLE_PATH}/bootstrap/containers/": self._create_mock_directory([]),
        }

        archive = make_archive(archive_map)
        log_analyzer = LogAnalyzer(archive)
        result = signature.analyze(log_analyzer)

        assert result is not None
        assert result.severity == "warning"
        assert "Host bootstrap (6 total crashes)" in result.content
        assert "etcd: 2 crash(es)" in result.content
        assert "kube-apiserver: 2 crash(es)" in result.content
        assert "kube-controller-manager: 1 crash(es)" in result.content
        assert "kube-scheduler: 1 crash(es)" in result.content

    def test_many_crashes_error_severity(self) -> None:
        """Test ContainerCrashAnalysis with many crashes (error severity)."""
        signature = ContainerCrashAnalysis()

        # Create kubelet log with 12 crashes (should trigger error)
        crashes = []
        for i in range(12):
            crashes.append(
                {
                    "timestamp": f"Sep 17 14:{35+i//2}:{(i % 2)*30:02d}",
                    "container": f"container-{i % 3}",
                }
            )

        kubelet_log = self._create_kubelet_log_with_crashes(crashes)

        archive_map = {
            f"{LOG_BUNDLE_PATH}/bootstrap/journals/kubelet.log": kubelet_log,
            f"{LOG_BUNDLE_PATH}/bootstrap/containers/": self._create_mock_directory([]),
        }

        archive = make_archive(archive_map)
        log_analyzer = LogAnalyzer(archive)
        result = signature.analyze(log_analyzer)

        assert result is not None
        assert result.severity == "error"
        assert "Host bootstrap (12 total crashes)" in result.content

    def test_multiple_hosts_analysis(self) -> None:
        """Test ContainerCrashAnalysis with multiple hosts."""
        signature = ContainerCrashAnalysis()

        # Bootstrap host with 2 crashes
        bootstrap_crashes = [
            {"timestamp": "Sep 17 14:35:00", "container": "etcd"},
            {"timestamp": "Sep 17 14:36:00", "container": "etcd"},
        ]
        bootstrap_kubelet_log = self._create_kubelet_log_with_crashes(bootstrap_crashes)

        # Control plane host with 3 crashes
        cp_crashes = [
            {"timestamp": "Sep 17 14:35:00", "container": "kube-apiserver"},
            {"timestamp": "Sep 17 14:36:00", "container": "kube-apiserver"},
            {"timestamp": "Sep 17 14:37:00", "container": "kube-controller-manager"},
        ]
        cp_kubelet_log = self._create_kubelet_log_with_crashes(cp_crashes)

        archive_map = {
            f"{LOG_BUNDLE_PATH}/bootstrap/journals/kubelet.log": bootstrap_kubelet_log,
            f"{LOG_BUNDLE_PATH}/control-plane/": self._create_mock_directory(
                ["192.168.1.10"]
            ),
            f"{LOG_BUNDLE_PATH}/control-plane/192.168.1.10/journals/kubelet.log": cp_kubelet_log,
            f"{LOG_BUNDLE_PATH}/bootstrap/containers/": self._create_mock_directory([]),
            f"{LOG_BUNDLE_PATH}/control-plane/192.168.1.10/containers/": self._create_mock_directory(
                []
            ),
        }

        archive = make_archive(archive_map)
        log_analyzer = LogAnalyzer(archive)
        result = signature.analyze(log_analyzer)

        assert result is not None
        assert result.severity == "warning"  # 5 total crashes
        # Control plane host should be listed first (more crashes)
        assert "Host 192.168.1.10 (3 total crashes)" in result.content
        assert "Host bootstrap (2 total crashes)" in result.content

    def test_time_filtering_excludes_old_crashes(self) -> None:
        """Test that crashes outside 30-minute window are excluded."""
        signature = ContainerCrashAnalysis()

        # Create crashes: some recent, some old
        crashes = [
            {"timestamp": "Sep 17 14:05:00", "container": "old-container"},  # Too old
            {"timestamp": "Sep 17 14:35:00", "container": "recent-container"},  # Recent
            {"timestamp": "Sep 17 14:38:00", "container": "recent-container"},  # Recent
        ]

        # Create log with latest timestamp at 14:40:00
        kubelet_log = self._create_kubelet_log_with_crashes(crashes)

        archive_map = {
            f"{LOG_BUNDLE_PATH}/bootstrap/journals/kubelet.log": kubelet_log,
            f"{LOG_BUNDLE_PATH}/bootstrap/containers/": self._create_mock_directory([]),
        }

        archive = make_archive(archive_map)
        log_analyzer = LogAnalyzer(archive)
        result = signature.analyze(log_analyzer)

        assert result is not None
        # Should only count the 2 recent crashes, not the old one
        assert "Host bootstrap (2 total crashes)" in result.content
        assert "recent-container: 2 crash(es)" in result.content
        assert "old-container" not in result.content

    def test_missing_kubelet_log(self) -> None:
        """Test ContainerCrashAnalysis when kubelet.log is missing."""
        signature = ContainerCrashAnalysis()

        archive = make_archive({})

        log_analyzer = LogAnalyzer(archive)
        result = signature.analyze(log_analyzer)

        assert result is None

    def test_invalid_timestamp_parsing(self) -> None:
        """Test ContainerCrashAnalysis with timestamp that fails parsing during filtering."""
        signature = ContainerCrashAnalysis()

        container = "test-container"
        pod_name = f"{container}-k8s-masters1"
        namespace = "openshift-system"
        pod_uid = "5caccf7ea3d504f6eba4b8ea6c6ed537"

        kubelet_log_lines = [
            # Use invalid month that matches regex pattern but fails datetime parsing
            "Xxx 17 14:30:00 k8s-masters1 kubenswrapper[2575]: I0917 14:30:00.123456 2575 kubelet.go:123] Starting kubelet",
            f"Sep 17 14:35:00 k8s-masters1 kubenswrapper[2575]: E0917 14:35:00.402290 2575 pod_workers.go:1301] "
            f'"Error syncing pod, skipping" err="failed to \\"StartContainer\\" for \\"{container}\\" with '
            f'CrashLoopBackOff: \\"back-off 10s restarting failed container={container} pod={pod_name}_{namespace}'
            f'({pod_uid})\\"" pod="{namespace}/{pod_name}" podUID="{pod_uid}"',
            "Sep 17 14:40:00 k8s-masters1 kubenswrapper[2575]: I0917 14:40:00.123456 2575 kubelet.go:789] Latest log entry",
        ]

        archive_map = {
            f"{LOG_BUNDLE_PATH}/bootstrap/journals/kubelet.log": "\n".join(
                kubelet_log_lines
            ),
            f"{LOG_BUNDLE_PATH}/bootstrap/containers/": self._create_mock_directory([]),
        }

        archive = make_archive(archive_map)
        log_analyzer = LogAnalyzer(archive)
        result = signature.analyze(log_analyzer)

        assert result is not None
        # Should still count the crash even with invalid timestamp parsing in a previous line
        assert "Host bootstrap (1 total crashes)" in result.content

    def test_container_logs_retrieval(self) -> None:
        """Test container logs retrieval and formatting."""
        signature = ContainerCrashAnalysis()

        crashes = [{"timestamp": "Sep 17 14:35:00", "container": "test-app"}]
        kubelet_log = self._create_kubelet_log_with_crashes(crashes)

        log_file_name = "test-app-abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890.log"

        archive_map = {
            f"{LOG_BUNDLE_PATH}/bootstrap/journals/kubelet.log": kubelet_log,
            f"{LOG_BUNDLE_PATH}/bootstrap/containers/": self._create_mock_directory(
                [log_file_name]
            ),
            f"{LOG_BUNDLE_PATH}/bootstrap/containers/{log_file_name}": self._create_container_log_content(
                "test-app", 25  # More than 20 lines,
            ),
        }

        archive = make_archive(archive_map)
        log_analyzer = LogAnalyzer(archive)
        result = signature.analyze(log_analyzer)

        assert result is not None
        assert "test-app: 1 crash(es)" in result.content
        assert "Last 20 container logs:" in result.content
        assert "Container test-app log line 6" in result.content
        assert "Container test-app log line 25" in result.content
        assert (
            "Container test-app log line 3" not in result.content
        )  # Should be excluded

    def test_container_logs_not_found(self) -> None:
        """Test when container logs are not found."""
        signature = ContainerCrashAnalysis()

        crashes = [{"timestamp": "Sep 17 14:35:00", "container": "missing-container"}]
        kubelet_log = self._create_kubelet_log_with_crashes(crashes)

        archive_map = {
            f"{LOG_BUNDLE_PATH}/bootstrap/journals/kubelet.log": kubelet_log,
            f"{LOG_BUNDLE_PATH}/bootstrap/containers/": self._create_mock_directory(
                []
            ),  # No log files
        }

        archive = make_archive(archive_map)
        log_analyzer = LogAnalyzer(archive)
        result = signature.analyze(log_analyzer)

        assert result is not None
        assert "missing-container: 1 crash(es)" in result.content
        assert "(Container logs not found)" in result.content

    def test_containers_directory_not_found(self) -> None:
        """Test when containers directory is not found."""
        signature = ContainerCrashAnalysis()

        crashes = [{"timestamp": "Sep 17 14:35:00", "container": "test-container"}]
        kubelet_log = self._create_kubelet_log_with_crashes(crashes)

        archive_map = {
            f"{LOG_BUNDLE_PATH}/bootstrap/journals/kubelet.log": kubelet_log,
            # No containers directory
        }

        archive = make_archive(archive_map)
        log_analyzer = LogAnalyzer(archive)
        result = signature.analyze(log_analyzer)

        assert result is not None
        assert "test-container: 1 crash(es)" in result.content
        assert "(Container logs not found)" in result.content

    def test_exception_handling(self) -> None:
        """Test ContainerCrashAnalysis exception handling."""
        signature = ContainerCrashAnalysis()

        # Create a mock log_analyzer that raises an exception
        mock_log_analyzer = MagicMock()
        mock_log_analyzer.logs_archive.get.side_effect = Exception("Unexpected error")

        result = signature.analyze(mock_log_analyzer)

        assert result is None

    def test_host_analysis_exception_handling(self) -> None:
        """Test exception handling during host directory analysis."""
        signature = ContainerCrashAnalysis()

        crashes = [{"timestamp": "Sep 17 14:35:00", "container": "test-container"}]
        kubelet_log = self._create_kubelet_log_with_crashes(crashes)

        # Create a mock that will cause an exception during host analysis, not directory listing
        def mock_get_side_effect(path: str, **_kwargs: str) -> object:
            if "control-plane" in path:
                # Return a mock directory for control-plane
                return self._create_mock_directory(["192.168.1.10"])

            if "192.168.1.10/journals/kubelet.log" in path:
                # Cause an exception when trying to get the kubelet log for control plane
                raise PermissionError("Kubelet log access error")

            if "bootstrap/journals/kubelet.log" in path:
                return kubelet_log

            if "bootstrap/containers/" in path:
                return self._create_mock_directory([])

            raise FileNotFoundError(path)

        mock_archive = MagicMock()
        mock_archive.get.side_effect = mock_get_side_effect

        log_analyzer = LogAnalyzer(mock_archive)
        result = signature.analyze(log_analyzer)

        # Should still return result from bootstrap host despite control-plane error
        assert result is not None
        assert "Host bootstrap (1 total crashes)" in result.content

    def test_signature_name_property(self) -> None:
        """Test that signature name is set correctly."""
        assert ContainerCrashAnalysis().name == "ContainerCrashAnalysis"

    def test_empty_kubelet_log(self) -> None:
        """Test ContainerCrashAnalysis with empty kubelet log."""
        signature = ContainerCrashAnalysis()

        archive_map = {
            f"{LOG_BUNDLE_PATH}/bootstrap/journals/kubelet.log": "",  # Empty log
        }

        archive = make_archive(archive_map)
        log_analyzer = LogAnalyzer(archive)
        result = signature.analyze(log_analyzer)

        assert result is None

    def test_multiple_container_log_files(self) -> None:
        """Test handling multiple log files for the same container."""
        signature = ContainerCrashAnalysis()

        crashes = [{"timestamp": "Sep 17 14:35:00", "container": "multi-log-container"}]
        kubelet_log = self._create_kubelet_log_with_crashes(crashes)

        # Create multiple log files for the same container
        log_content_1 = self._create_container_log_content("multi-log-container", 10)
        log_content_2 = self._create_container_log_content("multi-log-container", 15)
        log_file_name_1 = "multi-log-container-21234567890abcdef1234567890abcdef1234567890abcdef1234567890abcde.log"
        log_file_name_2 = "multi-log-container-fedcba0987654321fedcba0987654321fedcba0987654321fedcba09abcdef12.log"

        archive_map = {
            f"{LOG_BUNDLE_PATH}/bootstrap/journals/kubelet.log": kubelet_log,
            f"{LOG_BUNDLE_PATH}/bootstrap/containers/": self._create_mock_directory(
                [log_file_name_1, log_file_name_2]
            ),
            f"{LOG_BUNDLE_PATH}/bootstrap/containers/{log_file_name_1}": log_content_1,
            f"{LOG_BUNDLE_PATH}/bootstrap/containers/{log_file_name_2}": log_content_2,
        }

        archive = make_archive(archive_map)
        log_analyzer = LogAnalyzer(archive)
        result = signature.analyze(log_analyzer)

        assert result is not None
        assert "multi-log-container: 1 crash(es)" in result.content
        assert "Last 20 container logs:" in result.content
        # Should show logs from both files with separators
        assert f"--- {log_file_name_1} ---" in result.content
        assert f"--- {log_file_name_2} ---" in result.content
