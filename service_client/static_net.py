"""Static networking related functionality."""

import json
from typing import TypedDict, cast


class MacInterfaceMap(TypedDict):
    """Maps a NIC to a MAC Address."""

    logical_nic_name: str
    mac_address: str


class HostStaticNetworkConfig(TypedDict):
    """Matches the structure in the Assisted Installer API."""

    mac_interface_map: list[MacInterfaceMap]
    network_yaml: str


def add_or_update_static_host_config(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    existing_static_network_config: str | None,
    dns_server: str,
    mac_address: str,
    ip_address: str,
    subnet_prefix_len: int,
    gateway_address: str,
) -> list[HostStaticNetworkConfig]:
    """Generate and append or replace the config for a given mac address."""
    config: list[HostStaticNetworkConfig] = []
    if existing_static_network_config:
        config = [
            cast(HostStaticNetworkConfig, d)
            for d in json.loads(existing_static_network_config)
        ]

    i = find_host_config_index_for_mac(mac_address, config)
    if i is None:
        host_conf = HostStaticNetworkConfig(
            {
                "mac_interface_map": [
                    {
                        "logical_nic_name": "eth0",
                        "mac_address": mac_address,
                    }
                ],
                "network_yaml": "",
            }
        )
        config.append(host_conf)
        i = len(config) - 1

    config[i]["network_yaml"] = generate_basic_nmstate_yaml(
        dns_server,
        ip_address,
        subnet_prefix_len,
        gateway_address,
    )

    return config


def find_host_config_index_for_mac(
    mac_address: str, host_configs: list[HostStaticNetworkConfig]
) -> int | None:
    """Find the index of the host config for the given mac_address.

    Do a simple linear search since the list should be fairly small. The returned config refers to
    the original object in the list.
    """
    for i, c in enumerate(host_configs):
        for m in c["mac_interface_map"]:
            if m["mac_address"].lower() == mac_address.lower():
                return i
    return None


def generate_basic_nmstate_yaml(
    dns_server: str,
    ip_address: str,
    subnet_prefix_len: int,
    gateway_address: str,
) -> str:
    """Generate a basic NMState config with the given parameters."""
    return f"""
interfaces:
  - name: eth0
    type: ethernet
    state: up
    ipv4:
      address:
        - ip: {ip_address}
          prefix-length: {subnet_prefix_len}
      enabled: true
      dhcp: false
dns-resolver:
  config:
    server:
      - "{dns_server}"
routes:
  config:
    - destination: 0.0.0.0/0
      next-hop-address: {gateway_address}
      next-hop-interface: eth0
      table-id: 254
"""


def remove_static_host_config(
    existing_static_network_config: str | None,
    mac_address: str,
) -> list[HostStaticNetworkConfig]:
    """Remove the static config for the given MAC."""
    config: list[HostStaticNetworkConfig] = []
    if existing_static_network_config:
        config = [
            cast(HostStaticNetworkConfig, d)
            for d in json.loads(existing_static_network_config)
        ]

    i = find_host_config_index_for_mac(mac_address, config)
    if i is not None:
        del config[i]
    else:
        raise ValueError(f"host config for mac address {mac_address} does not exist")

    return config
