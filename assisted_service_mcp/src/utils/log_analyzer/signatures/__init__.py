"""
Signature analysis modules for OpenShift Assisted Installer logs.
"""

import sys
import inspect

from .base import Signature, ErrorSignature, SignatureResult

# Import all individual signature classes
# These are used dynamically via inspect.getmembers(), so we suppress unused import warnings
from .components_version_signature import ComponentsVersionSignature  # noqa: F401
from .sno_hostname_has_etcd import SNOHostnameHasEtcd  # noqa: F401
from .api_invalid_certificate_signature import (
    ApiInvalidCertificateSignature,  # noqa: F401
)
from .api_expired_certificate_signature import (
    ApiExpiredCertificateSignature,  # noqa: F401
)
from .release_pull_error_signature import ReleasePullErrorSignature  # noqa: F401
from .error_on_cleanup_install_device import ErrorOnCleanupInstallDevice  # noqa: F401
from .missing_mc import MissingMC  # noqa: F401
from .error_creating_read_write_layer import ErrorCreatingReadWriteLayer  # noqa: F401
from .sno_machine_cidr_signature import SNOMachineCidrSignature  # noqa: F401
from .duplicate_vip import DuplicateVIP  # noqa: F401
from .nameserver_in_cluster_network import NameserverInClusterNetwork  # noqa: F401
from .networks_mtu_mismatch import NetworksMtuMismatch  # noqa: F401
from .dual_stack_bad_route import DualStackBadRoute  # noqa: F401
from .dualstackr_dns_bug import DualstackrDNSBug  # noqa: F401
from .user_managed_networking_load_balancer import (
    UserManagedNetworkingLoadBalancer,  # noqa: F401
)
from .slow_image_download_signature import SlowImageDownloadSignature  # noqa: F401
from .libvirt_reboot_flag_signature import LibvirtRebootFlagSignature  # noqa: F401
from .ip_changed_after_reboot import IpChangedAfterReboot  # noqa: F401
from .events_installation_attempts import EventsInstallationAttempts  # noqa: F401
from .controller_warnings import ControllerWarnings  # noqa: F401
from .user_has_logged_into_cluster import UserHasLoggedIntoCluster  # noqa: F401
from .failed_request_triggers_host_timeout import (
    FailedRequestTriggersHostTimeout,  # noqa: F401
)
from .controller_failed_to_start import ControllerFailedToStart  # noqa: F401
from .machine_config_daemon_error_extracting import (
    MachineConfigDaemonErrorExtracting,  # noqa: F401
)
from .container_crash_analysis import ContainerCrashAnalysis  # noqa: F401

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
