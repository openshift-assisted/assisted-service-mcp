"""
OpenShift Assisted Installer Log Analyzer.

A standalone tool for analyzing OpenShift Assisted Installer logs.
"""

from .api_client import AssistedInstallerAPIClient
from .log_analyzer import LogAnalyzer
from .signatures import ALL_SIGNATURES, SignatureResult

__version__ = "1.0.0"
__all__ = [
    "AssistedInstallerAPIClient",
    "LogAnalyzer",
    "ALL_SIGNATURES",
    "SignatureResult",
]
