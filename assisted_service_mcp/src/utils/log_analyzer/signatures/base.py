"""
Base signature classes for OpenShift Assisted Installer log analysis.
"""

import abc
import logging
from typing import Optional, Any, Sequence

import dateutil.parser
from tabulate import tabulate

logger = logging.getLogger(__name__)


class SignatureResult:
    """Result of a signature analysis."""

    def __init__(
        self, signature_name: str, title: str, content: str = "", severity: str = "info"
    ):
        """
        Initialize a signature result.

        Args:
            signature_name: Name of the signature class
            title: Title of the analysis
            content: Analysis content/report
            severity: Severity level (info, warning, error)
        """
        self.signature_name = signature_name
        self.title = title
        self.content = content
        self.severity = severity

    def __str__(self) -> str:
        """String representation of the result."""
        if not self.content:
            return ""

        header = f"=== {self.title} ==="
        if self.severity == "error":
            header = f"ERROR: {header}"
        elif self.severity == "warning":
            header = f"WARNING: {header}"
        else:
            header = f"{header}"

        return f"{header}\n{self.content}\n"


class Signature(abc.ABC):
    """Base class for signature analysis."""

    logs_required = True

    def __init__(self):
        """Initialize the signature."""
        self.name = self.__class__.__name__

    @abc.abstractmethod
    def analyze(self, log_analyzer) -> Optional[SignatureResult]:
        """
        Analyze the logs and return a result if relevant.

        Args:
            log_analyzer: LogAnalyzer instance with access to logs

        Returns:
            SignatureResult if analysis finds something relevant, None otherwise
        """

    @staticmethod
    def generate_table(data: Sequence[dict[str, Any]]) -> str:
        """Generate a formatted table from data."""
        if not data:
            return "No data available"
        return tabulate(data, headers="keys", tablefmt="grid")

    @staticmethod
    def format_time(time_str: str) -> str:
        """Format time string for display."""
        try:
            return dateutil.parser.isoparse(time_str).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return time_str


class ErrorSignature(Signature, abc.ABC):
    """
    ErrorSignature is a Signature that represents error conditions.
    It optionally adds function impact and custom labels when issues are found.
    """

    def __init__(self, function_impact_label=None, label=None):
        """
        Initialize error signature.

        Args:
            function_impact_label: Optional function impact classification
            label: Optional custom label for categorization
        """
        super().__init__()
        self._function_impact_label = function_impact_label
        self._label = label

    def create_result(
        self, title: str, content: str, severity: str = "error"
    ) -> SignatureResult:
        """
        Create a SignatureResult with error severity by default.

        Args:
            title: Title of the error analysis
            content: Description of the error found
            severity: Severity level (defaults to "error")

        Returns:
            SignatureResult for this error signature
        """
        return SignatureResult(
            signature_name=self.name, title=title, content=content, severity=severity
        )
