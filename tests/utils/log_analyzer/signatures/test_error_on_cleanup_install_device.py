"""
Unit tests for ErrorOnCleanupInstallDevice signature.
"""

from unittest.mock import MagicMock

from assisted_service_mcp.src.utils.log_analyzer.signatures.error_on_cleanup_install_device import (
    ErrorOnCleanupInstallDevice,
)


class TestErrorOnCleanupInstallDevice:
    """Test cases for ErrorOnCleanupInstallDevice signature."""

    def test_no_errors_returns_none(self) -> None:
        """Test that signature returns None when no cleanup errors are found."""
        signature = ErrorOnCleanupInstallDevice()
        log_analyzer = MagicMock()

        log_analyzer.metadata = {"hosts": [{"id": "host1", "hostname": "test-host"}]}
        log_analyzer.get_host_log_file.return_value = "Some other log content without errors"

        result = signature.analyze(log_analyzer)

        assert result is None

    def test_basic_error_detected(self) -> None:
        """Test that signature detects basic cleanup error without quotes."""
        signature = ErrorOnCleanupInstallDevice()
        log_analyzer = MagicMock()

        log_analyzer.metadata = {"hosts": [{"id": "host1", "requested_hostname": "test-host"}]}
        log_content = 'msg="failed to prepare install device: permission denied"'
        log_analyzer.get_host_log_file.return_value = log_content

        result = signature.analyze(log_analyzer)

        assert result is not None
        assert result.title == "Non-fatal error on cleanupInstallDevice"
        assert result.severity == "warning"
        assert "test-host" in result.content
        assert "failed to prepare install device: permission denied" in result.content

    def test_error_with_embedded_quotes(self) -> None:
        """Test that signature captures full message with embedded quotes (greedy quantifier)."""
        signature = ErrorOnCleanupInstallDevice()
        log_analyzer = MagicMock()

        log_analyzer.metadata = {"hosts": [{"id": "host1", "hostname": "test-host"}]}
        # Message contains quoted device name "sda" - should capture full message, not stop at first quote
        log_content = 'msg="failed to prepare install device for "sda": permission denied"'
        log_analyzer.get_host_log_file.return_value = log_content

        result = signature.analyze(log_analyzer)

        assert result is not None
        # Should capture the full message including the quoted device name
        assert 'failed to prepare install device for "sda": permission denied' in result.content
        # Should NOT truncate at first embedded quote
        assert "failed to prepare install device for " not in result.content.split("\n")

    def test_message_truncation_at_200_chars(self) -> None:
        """Test that messages longer than 200 chars are truncated by the regex."""
        signature = ErrorOnCleanupInstallDevice()
        log_analyzer = MagicMock()

        log_analyzer.metadata = {"hosts": [{"id": "host1", "requested_hostname": "test-host"}]}
        # Create a message that's exactly at the boundary
        # The regex captures "failed to prepare install device" + up to 200 more chars
        # Total in the capture group: "failed to prepare install device" (32 chars) + 200 = 232 chars max
        long_error = "A" * 200  # Exactly at the limit
        log_content = f'msg="failed to prepare install device{long_error}"'
        log_analyzer.get_host_log_file.return_value = log_content

        result = signature.analyze(log_analyzer)

        assert result is not None
        # The captured message should be exactly "failed to prepare install device" + 200 A's
        assert "A" * 200 in result.content

        # Now test with a message that exceeds the limit - the quote comes after 200 chars
        # This should NOT match because the closing quote is beyond the .{0,200} range
        log_analyzer.metadata = {"hosts": [{"id": "host2", "requested_hostname": "test-host-2"}]}
        long_error_exceeded = "A" * 250  # Exceeds the limit
        log_content_exceeded = f'msg="failed to prepare install device{long_error_exceeded}"'
        log_analyzer.get_host_log_file.return_value = log_content_exceeded

        result2 = signature.analyze(log_analyzer)

        # Should not match at all because closing quote is too far
        assert result2 is None

    def test_multiple_hosts_with_errors(self) -> None:
        """Test that signature detects errors on multiple hosts."""
        signature = ErrorOnCleanupInstallDevice()
        log_analyzer = MagicMock()

        log_analyzer.metadata = {
            "hosts": [
                {"id": "host1", "requested_hostname": "test-host-1"},
                {"id": "host2", "requested_hostname": "test-host-2"},
            ]
        }

        def mock_get_log(host_id, log_file):
            if host_id == "host1":
                return 'msg="failed to prepare install device: error on host 1"'
            elif host_id == "host2":
                return 'msg="failed to prepare install device: error on host 2"'
            raise FileNotFoundError()

        log_analyzer.get_host_log_file.side_effect = mock_get_log

        result = signature.analyze(log_analyzer)

        assert result is not None
        assert "test-host-1" in result.content
        assert "test-host-2" in result.content
        assert "error on host 1" in result.content
        assert "error on host 2" in result.content

    def test_mixed_hosts_some_with_errors(self) -> None:
        """Test signature with some hosts having errors and some without."""
        signature = ErrorOnCleanupInstallDevice()
        log_analyzer = MagicMock()

        log_analyzer.metadata = {
            "hosts": [
                {"id": "host1", "requested_hostname": "test-host-1"},
                {"id": "host2", "requested_hostname": "test-host-2"},
            ]
        }

        def mock_get_log(host_id, log_file):
            if host_id == "host1":
                return 'msg="failed to prepare install device: error"'
            elif host_id == "host2":
                return "No errors in this log"
            raise FileNotFoundError()

        log_analyzer.get_host_log_file.side_effect = mock_get_log

        result = signature.analyze(log_analyzer)

        assert result is not None
        assert "test-host-1" in result.content
        assert "test-host-2" not in result.content

    def test_missing_installer_logs(self) -> None:
        """Test that signature handles missing installer.logs gracefully."""
        signature = ErrorOnCleanupInstallDevice()
        log_analyzer = MagicMock()

        log_analyzer.metadata = {"hosts": [{"id": "host1", "hostname": "test-host"}]}
        log_analyzer.get_host_log_file.side_effect = FileNotFoundError()

        result = signature.analyze(log_analyzer)

        assert result is None

    def test_no_hosts_in_cluster(self) -> None:
        """Test that signature handles cluster with no hosts."""
        signature = ErrorOnCleanupInstallDevice()
        log_analyzer = MagicMock()

        log_analyzer.metadata = {"hosts": []}

        result = signature.analyze(log_analyzer)

        assert result is None

    def test_host_without_hostname(self) -> None:
        """Test that signature handles hosts without hostname gracefully."""
        signature = ErrorOnCleanupInstallDevice()
        log_analyzer = MagicMock()

        # Host without hostname field - get_hostname helper should handle this
        log_analyzer.metadata = {"hosts": [{"id": "host1"}]}
        log_content = 'msg="failed to prepare install device: error"'
        log_analyzer.get_host_log_file.return_value = log_content

        result = signature.analyze(log_analyzer)

        assert result is not None
        # Should still create result even without hostname

    def test_result_contains_warning_message(self) -> None:
        """Test that result contains appropriate warning about non-fatal nature."""
        signature = ErrorOnCleanupInstallDevice()
        log_analyzer = MagicMock()

        log_analyzer.metadata = {"hosts": [{"id": "host1", "hostname": "test-host"}]}
        log_content = 'msg="failed to prepare install device: error"'
        log_analyzer.get_host_log_file.return_value = log_content

        result = signature.analyze(log_analyzer)

        assert result is not None
        assert "does not block installation" in result.content
        assert "cleanupInstallDevice" in result.content

    def test_signature_name_property(self) -> None:
        """Test that signature name is set correctly."""
        signature = ErrorOnCleanupInstallDevice()
        assert signature.name == "ErrorOnCleanupInstallDevice"
