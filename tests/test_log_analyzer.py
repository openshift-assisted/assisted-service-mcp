import asyncio
from typing import Any, Mapping
from unittest.mock import AsyncMock, MagicMock


def make_archive(get_map: Mapping[str, object]) -> Any:
    """Create a fake archive with a .get(path) API from a mapping."""

    class _A:
        def get(
            self, path: str, **kwargs: Any  # pylint: disable=unused-argument
        ) -> object:
            if path in get_map:
                return get_map[path]
            raise FileNotFoundError(path)

    return _A()


def test_cluster_analyzer_metadata_and_events_partitioning() -> None:
    """Test that the cluster analyzer correctly handles cluster metadata and events partitioning."""
    from assisted_service_mcp.src.utils.log_analyzer.log_analyzer import ClusterAnalyzer

    ca = ClusterAnalyzer()
    ca.set_cluster_metadata(
        {
            "cluster": {
                "install_started_at": "2025-01-01T11:11:00Z",
                "hosts": [
                    {"id": "h1", "requested_hostname": "h1-hostname"},
                    {
                        "id": "h2",
                        "requested_hostname": "h2",
                        "deleted_at": "2025-01-01T10:11:00Z",
                    },
                ],
            }
        }
    )
    ca.set_cluster_events(
        [
            {
                "name": "example_event",
                "event_time": "2025-01-01T11:11:00Z",
                "host_id": "h1",
            },
            {
                "name": "cluster_installation_reset",
                "message": "Cluster installation reset 1",
                "host_id": "h1",
            },
            {
                "name": "example_recent_event",
                "event_time": "2025-01-01T11:11:01Z",
                "message": "Most recent event",
                "host_id": "h1",
            },
        ]
    )
    assert ca.metadata is not None
    assert ca.metadata["cluster"]["install_started_at"] == "2025-01-01T11:11:00Z"
    # deleted host should be removed from hosts list
    assert ca.metadata["cluster"]["hosts"] == [
        {"id": "h1", "requested_hostname": "h1-hostname"}
    ]
    assert ca.cluster_events is not None
    assert ca.get_all_cluster_events() == [
        {
            "name": "example_event",
            "event_time": "2025-01-01T11:11:00Z",
            "host_id": "h1",
        },
        {
            "name": "cluster_installation_reset",
            "message": "Cluster installation reset 1",
            "host_id": "h1",
        },
        {
            "name": "example_recent_event",
            "event_time": "2025-01-01T11:11:01Z",
            "message": "Most recent event",
            "host_id": "h1",
        },
    ]
    # last install cluster events should be the most recent event after the reset event
    assert ca.get_last_install_cluster_events() == [
        {
            "name": "example_recent_event",
            "event_time": "2025-01-01T11:11:01Z",
            "message": "Most recent event",
            "host_id": "h1",
        }
    ]
    assert ca.get_events_by_host() == {
        "h1": [
            {
                "name": "example_recent_event",
                "event_time": "2025-01-01T11:11:01Z",
                "message": "Most recent event",
                "host_id": "h1",
            }
        ]
    }
    # get hostname should return the requested hostname of the host
    assert (
        ca.get_hostname({"id": "h1", "requested_hostname": "h1-hostname"})
        == "h1-hostname"
    )


def test_log_analyzer_metadata_and_events_partitioning() -> None:
    from assisted_service_mcp.src.utils.log_analyzer.log_analyzer import LogAnalyzer

    # minimal metadata and events
    md = {
        "cluster": {
            "install_started_at": "2025-01-01T00:00:00Z",
            "hosts": [
                {"id": "h1", "deleted_at": "2024-12-31T23:00:00Z"},
                {"id": "h2"},
            ],
        }
    }
    events = [
        {"name": "something"},
        {"name": "cluster_installation_reset"},
        {"name": "something_else", "host_id": "h2"},
    ]

    archive = make_archive(
        {
            "cluster_metadata.json": "{}",  # will be overridden below to inject md
            "cluster_events.json": "[]",  # overridden to inject events
        }
    )

    # monkeypatch the archive.get to return our JSON strings
    def _get(path: str, **kwargs: Any) -> str:  # pylint: disable=unused-argument
        if path == "cluster_metadata.json":
            import json

            return json.dumps(md["cluster"])  # analyzer wraps it into {"cluster":...}
        if path == "cluster_events.json":
            import json

            return json.dumps(events)
        raise FileNotFoundError(path)

    archive.get = _get  # type: ignore[attr-defined]

    la = LogAnalyzer(archive)  # type: ignore[arg-type]
    m = la.metadata
    assert m is not None
    assert "deleted_hosts" in m["cluster"] and len(m["cluster"]["deleted_hosts"]) == 1
    # last partition should only include post-reset events
    last_events = la.get_last_install_cluster_events()
    assert last_events and last_events[0]["name"] == "something_else"
    # grouped by host
    by_host = la.get_events_by_host()
    assert "h2" in by_host and by_host["h2"][0]["name"] == "something_else"


def test_log_analyzer_host_log_paths() -> None:
    from assisted_service_mcp.src.utils.log_analyzer.log_analyzer import LogAnalyzer

    # first simulate new-path miss, then old-path hit
    def _get(path: str, **kwargs: Any) -> str:  # pylint: disable=unused-argument
        # New format contains ".tar/.tar.gz/..." pattern
        if ".tar/.tar.gz/logs_host_hX/agent.logs" in path:
            raise FileNotFoundError(path)
        # Old format ends with ".tar.gz/logs_host_hX/agent.logs"
        if path.endswith(".tar.gz/logs_host_hX/agent.logs"):
            return "old"
        raise FileNotFoundError(path)

    archive = make_archive({})
    archive.get = _get  # type: ignore[attr-defined]
    la = LogAnalyzer(archive)  # type: ignore[arg-type]
    content = la.get_host_log_file("hX", "agent.logs")
    assert content == "old"


def test_main_analyze_cluster_runs_signatures() -> None:
    from assisted_service_mcp.src.utils.log_analyzer import main as main_mod

    fake_archive = MagicMock()
    fake_archive.get.return_value = (
        '{"cluster": {"install_started_at": "2025-01-01T00:00:00Z", "hosts": []}}'
    )

    # Mock the cluster object returned by get_cluster
    fake_cluster = MagicMock()
    fake_cluster.logs_info = "completed"  # Trigger the logs path
    fake_cluster.to_dict.return_value = {
        "install_started_at": "2025-01-01T00:00:00Z",
        "hosts": [],
    }

    fake_client = AsyncMock()
    fake_client.get_cluster.return_value = fake_cluster
    fake_client.get_cluster_logs.return_value = fake_archive
    fake_client.get_events.return_value = "[]"  # JSON string

    # Run with an empty signature list to ensure happy path
    async def run() -> None:
        results = await main_mod.analyze_cluster(
            "cid", fake_client, specific_signatures=[]
        )
        assert isinstance(results, list)

    asyncio.run(run())


def test_main_analyze_cluster_runs_signatures_no_logs() -> None:
    """Test that the main function runs signatures when no logs are available."""
    from assisted_service_mcp.src.utils.log_analyzer import main as main_mod

    # Mock the cluster object returned by get_cluster
    fake_cluster = MagicMock()
    fake_cluster.to_dict.return_value = {
        "cluster": {
            "install_started_at": "2025-01-01T00:00:00Z",
            "hosts": [
                {
                    "id": "h1",
                    "requested_hostname": "etcd-h1",  # should trigger SNOHostnameHasEtcd signature
                },
            ],
            "high_availability_mode": "None",
        }
    }
    fake_cluster.logs_info = "not_completed"

    fake_client = AsyncMock()
    fake_client.get_cluster.return_value = fake_cluster
    # should trigger SlowImageDownloadSignature signature
    fake_client.get_events.return_value = '[{"name": "slow_image_download", "event_time": "2025-01-01T00:00:00Z", "message": "Host h1: New image status quay.io/openshift-release-dev/ocp-release:4.19.12-x86_64. result: downloaded; download rate: 8.0 MBps"}]'  # JSON string

    # Run with an empty signature list should run all signatures that don't require logs
    results = asyncio.run(
        main_mod.analyze_cluster("cid", fake_client, specific_signatures=[])
    )
    assert isinstance(results, list)
    assert len(results) == 2
    for result in results:
        assert result.title in ["No etcd in SNO hostname", "Slow Image Download"]
        if result.title in "Slow Image Download":
            assert "Detected slow image download rate (MBps):" in result.content


def test_does_run_signature_if_logs_are_available() -> None:
    """Test that a signature that requires logs runs if logs are available."""
    from assisted_service_mcp.src.utils.log_analyzer import main as main_mod

    fake_archive = MagicMock()
    # These controller logs should trigger ApiInvalidCertificateSignature
    fake_archive.get.return_value = 'time="2025-01-01T00:00:00Z" level=error msg="x509: certificate is valid for 127.0.0.1, not 192.168.1.1"'

    # Mock the cluster object returned by get_cluster
    fake_cluster = MagicMock()
    fake_cluster.to_dict.return_value = {
        "install_started_at": "2025-01-01T00:00:00Z",
        "hosts": [],
    }
    fake_cluster.logs_info = "completed"

    fake_client = AsyncMock()
    fake_client.get_cluster.return_value = fake_cluster
    # This event should trigger SlowImageDownloadSignature signature, which should not run
    fake_client.get_events.return_value = '[{"name": "slow_image_download", "event_time": "2025-01-01T00:00:00Z", "message": "Host h1: New image status quay.io/openshift-release-dev/ocp-release:4.19.12-x86_64. result: downloaded; download rate: 8.0 MBps"}]'  # JSON string
    # This should not be called
    fake_client.get_cluster_logs.return_value = fake_archive

    # Run with APIInvalidCertificateSignature, which should run if logs are available
    results = asyncio.run(
        main_mod.analyze_cluster(
            "cid", fake_client, specific_signatures=["ApiInvalidCertificateSignature"]
        )
    )
    assert isinstance(results, list)
    assert len(results) == 1
    assert results[0].title == "Invalid SAN values on certificate for AI API"
    assert results[0].severity == "error"
    assert "x509: certificate is valid for" in results[0].content


def test_does_not_run_signature_if_logs_are_not_available() -> None:
    """Test that a signature that requires logs does not run if logs are not available."""
    from assisted_service_mcp.src.utils.log_analyzer import main as main_mod

    fake_archive = MagicMock()
    # These controller logs should trigger ApiInvalidCertificateSignature, which should not run because logs are not available
    fake_archive.get.return_value = 'time="2025-01-01T00:00:00Z" level=error msg="x509: certificate is valid for 127.0.0.1, not 192.168.1.1"'

    # Mock the cluster object returned by get_cluster
    fake_cluster = MagicMock()
    fake_cluster.to_dict.return_value = {
        "install_started_at": "2025-01-01T00:00:00Z",
        "hosts": [],
    }
    fake_cluster.logs_info = "not_completed"

    fake_client = AsyncMock()
    fake_client.get_cluster.return_value = fake_cluster
    # This event should trigger SlowImageDownloadSignature signature, which should not run
    fake_client.get_events.return_value = '[{"name": "slow_image_download", "event_time": "2025-01-01T00:00:00Z", "message": "Host h1: New image status quay.io/openshift-release-dev/ocp-release:4.19.12-x86_64. result: downloaded; download rate: 8.0 MBps"}]'  # JSON string
    # This should not be called
    fake_client.get_cluster_logs.return_value = fake_archive

    # Run with ApiInvalidCertificateSignature, which shouldn't run if logs are not available
    results = asyncio.run(
        main_mod.analyze_cluster(
            "cid", fake_client, specific_signatures=["ApiInvalidCertificateSignature"]
        )
    )
    assert isinstance(results, list)
    assert len(results) == 0


def test_slow_image_download_signature_runs_no_logs() -> None:
    """Test that the slow image download signature runs when logs are not available."""
    from assisted_service_mcp.src.utils.log_analyzer import main as main_mod

    # Mock the cluster object returned by get_cluster
    fake_cluster = MagicMock()
    fake_cluster.to_dict.return_value = {
        "install_started_at": "2025-01-01T00:00:00Z",
        "hosts": [],
    }
    fake_cluster.logs_info = "not_completed"

    fake_client = AsyncMock()
    fake_client.get_cluster.return_value = fake_cluster
    fake_client.get_events.return_value = '[{"name": "image_download", "event_time": "2025-01-01T00:00:00Z", "message": "Host h1: New image status quay.io/openshift-release-dev/ocp-release:4.19.12-x86_64. result: downloaded; download rate: 8.0 MBps"}]'  # JSON string

    # Run with slow image download signature
    async def run() -> None:
        results = await main_mod.analyze_cluster(
            "cid", fake_client, specific_signatures=["SlowImageDownloadSignature"]
        )
        assert isinstance(results, list)
        assert len(results) == 1
        assert results[0].title == "Slow Image Download"
        assert results[0].severity == "warning"
        assert "Detected slow image download rate (MBps):" in results[0].content

    asyncio.run(run())


def test_basic_info_signature_runs() -> None:
    from assisted_service_mcp.src.utils.log_analyzer.log_analyzer import LogAnalyzer
    from assisted_service_mcp.src.utils.log_analyzer.signatures.basic_info import (
        ComponentsVersionSignature,
    )

    archive = make_archive(
        {
            "cluster_metadata.json": "{}",
            "cluster_events.json": "[]",
        }
    )
    la = LogAnalyzer(archive)  # type: ignore[arg-type]
    sig = ComponentsVersionSignature()
    # Should not raise, may return SignatureResult or None
    _ = sig.analyze(la)


def test_error_detection_signature_no_crash() -> None:
    from assisted_service_mcp.src.utils.log_analyzer.log_analyzer import LogAnalyzer
    from assisted_service_mcp.src.utils.log_analyzer.signatures.error_detection import (
        SNOHostnameHasEtcd,
    )

    archive = make_archive(
        {
            "cluster_metadata.json": "{}",
            "cluster_events.json": "[]",
            # controller logs not needed for this quick smoke; absence should be handled
        }
    )
    la = LogAnalyzer(archive)  # type: ignore[arg-type]
    sig = SNOHostnameHasEtcd()
    _ = sig.analyze(la)


def test_networking_signature_no_crash() -> None:
    from assisted_service_mcp.src.utils.log_analyzer.log_analyzer import LogAnalyzer
    from assisted_service_mcp.src.utils.log_analyzer.signatures.networking import (
        SNOMachineCidrSignature,
    )

    archive = make_archive(
        {
            "cluster_metadata.json": "{}",
            "cluster_events.json": "[]",
        }
    )
    la = LogAnalyzer(archive)  # type: ignore[arg-type]
    sig = SNOMachineCidrSignature()
    _ = sig.analyze(la)
