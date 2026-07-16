"""Unit tests for follow-up question generators."""

import pytest

from assisted_service_mcp.src.tools.followups import (
    _format,
    cluster_info_followups,
    create_cluster_followups,
    get_cluster_hosts_followups,
    installation_progress_followups,
    list_clusters_followups,
)


SEPARATOR = "\n\n[IMPORTANT"


class TestFormat:
    def test_empty_list_returns_empty_string(self) -> None:
        assert _format([]) == ""

    def test_single_step(self) -> None:
        result = _format(["Do you want help?"])
        assert result.startswith(SEPARATOR)
        assert "1. Do you want help?" in result

    def test_multiple_steps(self) -> None:
        result = _format(["Step one", "Step two"])
        assert "1. Step one" in result
        assert "2. Step two" in result

    def test_includes_heading_instruction(self) -> None:
        result = _format(["Something"])
        assert "Suggested next steps" in result


class TestListClustersFollowups:
    def test_no_clusters(self) -> None:
        result = list_clusters_followups([])
        assert "create" in result.lower()

    def test_clusters_exist(self) -> None:
        clusters = [{"name": "c1", "id": "1", "status": "ready"}]
        result = list_clusters_followups(clusters)
        assert "cluster details" in result.lower()
        assert "new cluster" in result.lower()

    def test_pending_cluster_suggests_setup(self) -> None:
        clusters = [
            {"name": "c1", "id": "1", "status": "pending-for-input"},
            {"name": "c2", "id": "2", "status": "installed"},
        ]
        result = list_clusters_followups(clusters)
        assert "cluster setup" in result.lower()

    def test_no_pending_omits_setup_suggestion(self) -> None:
        clusters = [{"name": "c1", "id": "1", "status": "installed"}]
        result = list_clusters_followups(clusters)
        assert "pending" not in result.lower()


class TestClusterInfoFollowups:
    @pytest.mark.parametrize(
        "status",
        ["pending-for-input", "insufficient", "ready"],
    )
    def test_setup_statuses(self, status: str) -> None:
        result = cluster_info_followups(status)
        assert "cluster setup" in result.lower()
        assert "pre-install" in result.lower()

    def test_installing_status(self) -> None:
        result = cluster_info_followups("installing")
        assert "installation progress" in result.lower()

    def test_installed_status(self) -> None:
        result = cluster_info_followups("installed")
        assert "credentials" in result.lower()

    @pytest.mark.parametrize("status", ["error", "cancelled"])
    def test_error_statuses(self, status: str) -> None:
        result = cluster_info_followups(status)
        assert "log analysis" in result.lower()

    def test_unknown_status_returns_empty(self) -> None:
        result = cluster_info_followups("some-unknown-state")
        assert result == ""

    def test_none_status_returns_empty(self) -> None:
        result = cluster_info_followups("")
        assert result == ""


class TestCreateClusterFollowups:
    def test_contains_key_suggestions(self) -> None:
        result = create_cluster_followups()
        assert "pre-install configuration" in result.lower()
        assert "boot a host" in result.lower()
        assert "cluster setup" in result.lower()


class TestGetClusterHostsFollowups:
    def test_no_hosts(self) -> None:
        result = get_cluster_hosts_followups([], None)
        assert "host discovery" in result.lower()

    def test_hosts_discovered_pending(self) -> None:
        hosts = [{"id": "h1", "status": "known", "role": "auto-assign"}]
        result = get_cluster_hosts_followups(hosts, "pending-for-input")
        assert "role assignment" in result.lower()
        assert "network configuration" in result.lower()

    def test_installing(self) -> None:
        hosts = [{"id": "h1", "status": "installing", "role": "master"}]
        result = get_cluster_hosts_followups(hosts, "installing")
        assert "installation progress" in result.lower()

    def test_installed(self) -> None:
        hosts = [{"id": "h1", "status": "installed", "role": "master"}]
        result = get_cluster_hosts_followups(hosts, "installed")
        assert "credentials" in result.lower()


class TestInstallationProgressFollowups:
    def test_installing(self) -> None:
        result = installation_progress_followups("installing")
        assert "event details" in result.lower()

    def test_installed(self) -> None:
        result = installation_progress_followups("installed")
        assert "credentials" in result.lower()

    @pytest.mark.parametrize("status", ["error", "cancelled"])
    def test_error(self, status: str) -> None:
        result = installation_progress_followups(status)
        assert "log analysis" in result.lower()

    def test_unknown_returns_empty(self) -> None:
        result = installation_progress_followups("some-random")
        assert result == ""
