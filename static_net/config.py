"""infra env static_network_config field handling"""

import json
from typing import Any, TypedDict, cast

import yaml


class MacInterfaceMap(TypedDict):
    """Maps a NIC to a MAC Address."""

    logical_nic_name: str
    mac_address: str


class HostStaticNetworkConfig(TypedDict):
    """Matches the structure in the Assisted Installer API."""

    mac_interface_map: list[MacInterfaceMap]
    network_yaml: str


def remove_static_host_config_by_index(
    existing_static_network_config: str, index: int
) -> list[HostStaticNetworkConfig]:
    """Remove a single host's config by index position."""
    config = [
        cast(HostStaticNetworkConfig, d)
        for d in json.loads(existing_static_network_config)
    ]
    if index < 0:
        raise IndexError("negative indexes are not allowed")
    if index >= len(config):
        raise ValueError(
            f"static network config only has {len(config)} elements, cannot delete index {index}"
        )
    del config[index]
    return config


def add_or_replace_static_host_config_yaml(
    existing_static_network_config: str | None,
    index: int | None,
    new_nmstate_yaml: str,
) -> list[HostStaticNetworkConfig]:
    """Add/update a single host's config by index.

    Raises:
     - IndexError: if the index is out of range for the existing config
    """
    config: list[HostStaticNetworkConfig] = []
    if existing_static_network_config:
        config = [
            cast(HostStaticNetworkConfig, d)
            for d in json.loads(existing_static_network_config)
        ]

    host_config = _generate_host_static_config(new_nmstate_yaml)
    if index is None:
        config.append(host_config)
    else:
        if index < 0:
            raise IndexError("negative indexes are not allowed")
        if index >= len(config):
            raise IndexError(
                f"static network config only has {len(config)} elements, cannot replace index {index}"
            )
        config[index] = host_config

    return config


def _generate_host_static_config(nmstate_yaml: str) -> HostStaticNetworkConfig:
    nmstate = validate_and_parse_nmstate(nmstate_yaml)
    interfaces = nmstate.get("interfaces")
    name_and_mac_list: list[MacInterfaceMap] = [
        {
            "mac_address": i.get("mac-address"),
            "logical_nic_name": i.get("name"),
        }
        for i in interfaces
        if i.get("mac-address")
    ]
    if not name_and_mac_list:
        raise ValueError("At least one interface must be associated to a MAC Address")

    new_host: HostStaticNetworkConfig = {
        "mac_interface_map": name_and_mac_list,
        "network_yaml": nmstate_yaml,
    }
    return new_host


def validate_and_parse_nmstate(nmstate_yaml: str) -> Any:
    """Validate nmstate yaml and return it parsed.

    Raises:
     - ValueError: If the yaml is invalid is some way
    """
    # Eventually when nmstate 2.2.51 is released we should be able to validate the nmstate by doing:
    # libnmstate.validate(nmstate_yaml)
    # For now just make sure it is valid yaml
    try:
        return yaml.safe_load(nmstate_yaml)
    except yaml.YAMLError as e:
        raise ValueError("Invalid YAML") from e
