"""
Signature analysis modules for OpenShift Assisted Installer logs.
"""

import sys
import inspect

from .base import Signature, ErrorSignature, SignatureResult
from .basic_info import *  # noqa
from .error_detection import *  # noqa
from .performance import *  # noqa
from .networking import *  # noqa
from .advanced_analysis import *  # noqa
from .platform_specific import *  # noqa

# Collect all signatures from all modules
ALL_SIGNATURES = []

current_module = sys.modules[__name__]
for name, obj in inspect.getmembers(current_module):
    if (
        inspect.isclass(obj)
        and issubclass(obj, Signature)
        and obj is not Signature
        and obj is not ErrorSignature
        and obj is not SignatureResult
    ):
        ALL_SIGNATURES.append(obj)

# Sort by name for consistent ordering
ALL_SIGNATURES.sort(key=lambda x: x.__name__)

__all__ = ["Signature", "ErrorSignature", "SignatureResult", "ALL_SIGNATURES"]
