"""
OpenShift Assisted Installer Log Analyzer.

A standalone tool for analyzing OpenShift Assisted Installer logs.
"""

from .log_analyzer import ClusterAnalyzer, LogAnalyzer
from .signatures import ALL_SIGNATURES, SignatureResult

__version__ = "1.0.0"
__all__ = [
    "ClusterAnalyzer",
    "LogAnalyzer",
    "ALL_SIGNATURES",
    "SignatureResult",
]
