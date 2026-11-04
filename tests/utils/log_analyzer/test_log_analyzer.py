import asyncio
from collections.abc import Mapping
from typing import Any
from unittest.mock import MagicMock, patch


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


def test_log_analyzer_metadata_and_events_partitioning() -> None:
    from assisted_service_mcp.src.utils.log_analyzer.log_analyzer import LogAnalyzer

    # minimal metadata and events
    md = {
        "install_started_at": "2025-01-01T00:00:00Z",
        "hosts": [
            {"id": "h1", "deleted_at": "2024-12-31T23:00:00Z"},
            {"id": "h2"},
        ],
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

            return json.dumps(md)  # metadata is used directly without wrapping
        if path == "cluster_events.json":
            import json

            return json.dumps(events)
        raise FileNotFoundError(path)

    archive.get = _get  # type: ignore[attr-defined]

    la = LogAnalyzer(archive)  # type: ignore[arg-type]
    m = la.metadata
    assert m is not None
    assert "deleted_hosts" in m and len(m["deleted_hosts"]) == 1
    # Despite its name, get_all_cluster_events returns only the latest attempt.
    latest_events = la.get_all_cluster_events()
    assert [event["name"] for event in latest_events] == ["something_else"]

    last_events = la.get_last_install_cluster_events()
    assert last_events == latest_events


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


def test_runner_analyze_cluster_runs_all_when_unspecified() -> None:
    from assisted_service_mcp.src.utils.log_analyzer import runner as runner_mod

    signature_class = MagicMock()
    signature_class.__name__ = "TestSignature"
    fake_client = MagicMock()

    async def _get_logs(_cluster_id: str) -> MagicMock:
        return MagicMock()

    fake_client.get_cluster_logs = _get_logs  # type: ignore[attr-defined]

    with patch.object(runner_mod, "ALL_SIGNATURES", [signature_class]):
        results = asyncio.run(runner_mod.analyze_cluster("cid", fake_client))

    assert len(results) == 1
    signature_class.assert_called_once_with()
    signature_class.return_value.analyze.assert_called_once()


def test_runner_analyze_cluster_empty_signature_list_runs_none() -> None:
    from assisted_service_mcp.src.utils.log_analyzer import runner as runner_mod

    signature_class = MagicMock()
    signature_class.__name__ = "TestSignature"
    fake_client = MagicMock()

    async def _get_logs(_cluster_id: str) -> MagicMock:
        return MagicMock()

    fake_client.get_cluster_logs = _get_logs  # type: ignore[attr-defined]

    with patch.object(runner_mod, "ALL_SIGNATURES", [signature_class]):
        results = asyncio.run(
            runner_mod.analyze_cluster("cid", fake_client, specific_signatures=[])
        )

    assert results == []
    signature_class.assert_not_called()


def test_error_detection_signature_no_crash() -> None:
    from assisted_service_mcp.src.utils.log_analyzer.log_analyzer import LogAnalyzer
    from assisted_service_mcp.src.utils.log_analyzer.signatures.sno_hostname_has_etcd import (
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
    from assisted_service_mcp.src.utils.log_analyzer.signatures.sno_machine_cidr_signature import (
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
