"""Static networking related functionality."""

from .config import (
    add_or_replace_static_host_config_yaml,
    remove_static_host_config_by_index,
    validate_and_parse_nmstate,
)
from .template import NMStateTemplateParams, generate_nmstate_from_template

__all__ = [
    "NMStateTemplateParams",
    "add_or_replace_static_host_config_yaml",
    "generate_nmstate_from_template",
    "remove_static_host_config_by_index",
    "validate_and_parse_nmstate",
]
