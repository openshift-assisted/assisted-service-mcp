"""
Unit tests for SlowImageDownloadSignature.
"""

from unittest.mock import MagicMock
from typing import Dict, Any

from assisted_service_mcp.src.utils.log_analyzer.signatures.slow_image_download_signature import (
    SlowImageDownloadSignature,
)


def create_image_download_event(
    hostname: str, image: str, download_rate: str
) -> Dict[str, Any]:
    """Create a mock event with image download information."""
    return {
        "message": f"Host {hostname}: New image status {image}. result: success; download rate: {download_rate} MBps",
        "name": "image_download",
    }


class TestSlowImageDownloadSignature:
    """Test cases for SlowImageDownloadSignature."""

    def test_no_slow_downloads_returns_none(self) -> None:
        """Test that signature returns None when all downloads are fast."""
        signature = SlowImageDownloadSignature()
        log_analyzer = MagicMock()

        # All downloads are above the minimum threshold (10 MBps)
        events = [
            create_image_download_event("host1", "image1", "15.5"),
            create_image_download_event("host2", "image2", "20.0"),
            create_image_download_event("host3", "image3", "12.3"),
        ]
        log_analyzer.get_last_install_cluster_events.return_value = events

        result = signature.analyze(log_analyzer)

        assert result is None

    def test_slow_downloads_detected(self) -> None:
        """Test that signature detects slow downloads."""
        signature = SlowImageDownloadSignature()
        log_analyzer = MagicMock()

        # Mix of fast and slow downloads
        events = [
            create_image_download_event("host1", "image1", "15.5"),  # Fast
            create_image_download_event("host2", "image2", "5.2"),  # Slow
            create_image_download_event("host3", "image3", "8.1"),  # Slow
            create_image_download_event("host4", "image4", "20.0"),  # Fast
        ]
        log_analyzer.get_last_install_cluster_events.return_value = events

        result = signature.analyze(log_analyzer)

        assert result is not None
        assert result.title == "Slow Image Download"
        assert result.severity == "warning"
        assert "Detected slow image download rate" in result.content
        assert "host2" in result.content
        assert "host3" in result.content
        assert "image2" in result.content
        assert "image3" in result.content
        assert "5.2" in result.content
        assert "8.1" in result.content

    def test_all_slow_downloads(self) -> None:
        """Test that signature detects when all downloads are slow."""
        signature = SlowImageDownloadSignature()
        log_analyzer = MagicMock()

        events = [
            create_image_download_event("host1", "image1", "3.5"),
            create_image_download_event("host2", "image2", "7.8"),
            create_image_download_event("host3", "image3", "9.9"),
        ]
        log_analyzer.get_last_install_cluster_events.return_value = events

        result = signature.analyze(log_analyzer)

        assert result is not None
        assert result.title == "Slow Image Download"
        assert "host1" in result.content
        assert "host2" in result.content
        assert "host3" in result.content

    def test_download_rate_at_threshold(self) -> None:
        """Test that download rate exactly at threshold is not considered slow."""
        signature = SlowImageDownloadSignature()
        log_analyzer = MagicMock()

        # Exactly at threshold (10.0 MBps)
        events = [
            create_image_download_event("host1", "image1", "10.0"),
        ]
        log_analyzer.get_last_install_cluster_events.return_value = events

        result = signature.analyze(log_analyzer)

        assert result is None

    def test_download_rate_just_below_threshold(self) -> None:
        """Test that download rate just below threshold is detected."""
        signature = SlowImageDownloadSignature()
        log_analyzer = MagicMock()

        # Just below threshold (9.999 MBps)
        events = [
            create_image_download_event("host1", "image1", "9.999"),
        ]
        log_analyzer.get_last_install_cluster_events.return_value = events

        result = signature.analyze(log_analyzer)

        assert result is not None
        assert "host1" in result.content

    def test_no_image_download_events(self) -> None:
        """Test that signature returns None when there are no image download events."""
        signature = SlowImageDownloadSignature()
        log_analyzer = MagicMock()

        events = [
            {"message": "Some other event", "name": "other_event"},
            {"message": "Another event", "name": "another_event"},
        ]
        log_analyzer.get_last_install_cluster_events.return_value = events

        result = signature.analyze(log_analyzer)

        assert result is None

    def test_empty_events_list(self) -> None:
        """Test that signature handles empty events list."""
        signature = SlowImageDownloadSignature()
        log_analyzer = MagicMock()

        log_analyzer.get_last_install_cluster_events.return_value = []

        result = signature.analyze(log_analyzer)

        assert result is None

    def test_malformed_image_download_event(self) -> None:
        """Test that signature handles malformed image download events gracefully."""
        signature = SlowImageDownloadSignature()
        log_analyzer = MagicMock()

        events = [
            create_image_download_event(
                "host1", "image1", "5.0"
            ),  # Valid slow download
            {
                "message": "Host host2: Invalid format",
                "name": "image_download",
            },  # Malformed
            create_image_download_event(
                "host3", "image3", "8.0"
            ),  # Valid slow download
        ]
        log_analyzer.get_last_install_cluster_events.return_value = events

        result = signature.analyze(log_analyzer)

        assert result is not None
        # Should only include valid slow downloads
        assert "host1" in result.content
        assert "host3" in result.content
        assert "host2" not in result.content

    def test_exception_handling(self) -> None:
        """Test that signature handles exceptions gracefully."""
        signature = SlowImageDownloadSignature()
        log_analyzer = MagicMock()

        # Simulate an exception when getting events
        log_analyzer.get_last_install_cluster_events.side_effect = Exception(
            "Test error"
        )

        result = signature.analyze(log_analyzer)

        assert result is None

    def test_invalid_download_rate_format(self) -> None:
        """Test that signature handles invalid download rate formats gracefully."""
        signature = SlowImageDownloadSignature()
        log_analyzer = MagicMock()

        # Create event with invalid download rate that can't be converted to float
        events = [
            create_image_download_event("host1", "image1", "invalid"),
        ]
        log_analyzer.get_last_install_cluster_events.return_value = events

        # Should catch ValueError and return None (exception is logged but not raised)
        result = signature.analyze(log_analyzer)
        assert result is None

    def test_multiple_slow_downloads_same_host(self) -> None:
        """Test that signature detects multiple slow downloads from the same host."""
        signature = SlowImageDownloadSignature()
        log_analyzer = MagicMock()

        events = [
            create_image_download_event("host1", "image1", "4.5"),
            create_image_download_event("host1", "image2", "6.2"),
            create_image_download_event("host1", "image3", "7.8"),
        ]
        log_analyzer.get_last_install_cluster_events.return_value = events

        result = signature.analyze(log_analyzer)

        assert result is not None
        assert result.content.count("host1") == 3  # Should appear 3 times in the table
        assert "image1" in result.content
        assert "image2" in result.content
        assert "image3" in result.content

    def test_signature_name_property(self) -> None:
        """Test that signature name is set correctly."""
        signature = SlowImageDownloadSignature()
        assert signature.name == "SlowImageDownloadSignature"

    def test_minimum_download_rate_threshold(self) -> None:
        """Test that the minimum download rate threshold is correct."""
        signature = SlowImageDownloadSignature()
        assert signature.minimum_download_rate_mb == 10
