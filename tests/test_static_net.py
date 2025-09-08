# type: ignore
"""
Unit tests for the static_net module.
"""

import json
import pytest

from service_client.static_net import (
    add_or_update_static_host_config,
    find_host_config_index_for_mac,
    generate_basic_nmstate_yaml,
    remove_static_host_config,
)


class TestFindHostConfigIndexForMac:
    """Test cases for find_host_config_index_for_mac function."""

    def test_find_existing_mac_address(self):
        """Test finding an existing MAC address."""
        configs = [
            {
                "mac_interface_map": [
                    {
                        "logical_nic_name": "eth0",
                        "mac_address": "00:11:22:33:44:55",
                    }
                ],
                "network_yaml": "yaml1",
            },
            {
                "mac_interface_map": [
                    {
                        "logical_nic_name": "eth0",
                        "mac_address": "aa:bb:cc:dd:ee:ff",
                    }
                ],
                "network_yaml": "yaml2",
            },
        ]

        index = find_host_config_index_for_mac("aa:bb:cc:dd:ee:ff", configs)
        assert index == 1

    def test_find_nonexistent_mac_address(self):
        """Test searching for a MAC address that doesn't exist."""
        configs = [
            {
                "mac_interface_map": [
                    {
                        "logical_nic_name": "eth0",
                        "mac_address": "00:11:22:33:44:55",
                    }
                ],
                "network_yaml": "yaml1",
            }
        ]

        index = find_host_config_index_for_mac("ff:ff:ff:ff:ff:ff", configs)
        assert index is None

    def test_find_mac_in_multiple_interfaces(self):
        """Test finding MAC address when host has multiple interfaces."""
        configs = [
            {
                "mac_interface_map": [
                    {
                        "logical_nic_name": "eth0",
                        "mac_address": "00:11:22:33:44:55",
                    },
                    {
                        "logical_nic_name": "eth1",
                        "mac_address": "aa:bb:cc:dd:ee:ff",
                    },
                ],
                "network_yaml": "yaml1",
            }
        ]

        index = find_host_config_index_for_mac("aa:bb:cc:dd:ee:ff", configs)
        assert index == 0

    def test_find_mac_in_empty_list(self):
        """Test searching in an empty configuration list."""
        index = find_host_config_index_for_mac("00:11:22:33:44:55", [])
        assert index is None


class TestGenerateBasicNmstateYaml:
    """Test cases for generate_basic_nmstate_yaml function."""

    def test_generate_yaml_with_valid_parameters(self):
        """Test generating YAML with valid network parameters."""
        yaml_content = generate_basic_nmstate_yaml(
            dns_server="8.8.8.8",
            ip_address="192.168.1.100",
            subnet_prefix_len=24,
            gateway_address="192.168.1.1",
        )

        assert "8.8.8.8" in yaml_content
        assert "192.168.1.100" in yaml_content
        assert "prefix-length: 24" in yaml_content
        assert "192.168.1.1" in yaml_content


class TestAddOrUpdateStaticHostConfig:
    """Test cases for add_or_update_static_host_config function."""

    def test_add_new_host_config_to_empty_list(self):
        """Test adding a new host configuration to an empty list."""
        result = add_or_update_static_host_config(
            existing_static_network_config=None,
            dns_server="8.8.8.8",
            mac_address="00:11:22:33:44:55",
            ip_address="192.168.1.100",
            subnet_prefix_len=24,
            gateway_address="192.168.1.1",
        )

        assert len(result) == 1
        assert result[0]["mac_interface_map"][0]["mac_address"] == "00:11:22:33:44:55"
        assert result[0]["mac_interface_map"][0]["logical_nic_name"] == "eth0"
        assert "192.168.1.100" in result[0]["network_yaml"]

    def test_add_new_host_config_to_existing_list(self):
        """Test adding a new host configuration to an existing list."""
        existing_config = json.dumps(
            [
                {
                    "mac_interface_map": [
                        {
                            "logical_nic_name": "eth0",
                            "mac_address": "aa:bb:cc:dd:ee:ff",
                        }
                    ],
                    "network_yaml": "existing yaml",
                }
            ]
        )

        result = add_or_update_static_host_config(
            existing_static_network_config=existing_config,
            dns_server="8.8.8.8",
            mac_address="00:11:22:33:44:55",
            ip_address="192.168.1.100",
            subnet_prefix_len=24,
            gateway_address="192.168.1.1",
        )

        assert len(result) == 2
        # Verify the original config is preserved
        assert result[0]["mac_interface_map"][0]["mac_address"] == "aa:bb:cc:dd:ee:ff"
        assert result[0]["network_yaml"] == "existing yaml"
        # Verify the new config is added
        assert result[1]["mac_interface_map"][0]["mac_address"] == "00:11:22:33:44:55"
        assert "192.168.1.100" in result[1]["network_yaml"]

    def test_update_existing_host_config(self):
        """Test updating an existing host configuration."""
        existing_config = json.dumps(
            [
                {
                    "mac_interface_map": [
                        {
                            "logical_nic_name": "eth0",
                            "mac_address": "00:11:22:33:44:55",
                        }
                    ],
                    "network_yaml": "old yaml content",
                }
            ]
        )

        result = add_or_update_static_host_config(
            existing_static_network_config=existing_config,
            dns_server="1.1.1.1",
            mac_address="00:11:22:33:44:55",
            ip_address="10.0.0.50",
            subnet_prefix_len=16,
            gateway_address="10.0.0.1",
        )

        assert len(result) == 1
        assert result[0]["mac_interface_map"][0]["mac_address"] == "00:11:22:33:44:55"
        assert "10.0.0.50" in result[0]["network_yaml"]
        assert "1.1.1.1" in result[0]["network_yaml"]
        assert "old yaml content" not in result[0]["network_yaml"]

    def test_handle_invalid_json_config(self):
        """Test handling of invalid JSON in existing config."""
        with pytest.raises(json.JSONDecodeError):
            add_or_update_static_host_config(
                existing_static_network_config="invalid json",
                dns_server="8.8.8.8",
                mac_address="00:11:22:33:44:55",
                ip_address="192.168.1.100",
                subnet_prefix_len=24,
                gateway_address="192.168.1.1",
            )


class TestRemoveStaticHostConfig:
    """Test cases for remove_static_host_config function."""

    def test_remove_existing_host_config(self):
        """Test removing an existing host configuration."""
        existing_config = json.dumps(
            [
                {
                    "mac_interface_map": [
                        {
                            "logical_nic_name": "eth0",
                            "mac_address": "00:11:22:33:44:55",
                        }
                    ],
                    "network_yaml": "yaml1",
                },
                {
                    "mac_interface_map": [
                        {
                            "logical_nic_name": "eth0",
                            "mac_address": "aa:bb:cc:dd:ee:ff",
                        }
                    ],
                    "network_yaml": "yaml2",
                },
            ]
        )

        result = remove_static_host_config(
            existing_static_network_config=existing_config,
            mac_address="00:11:22:33:44:55",
        )

        assert len(result) == 1
        assert result[0]["mac_interface_map"][0]["mac_address"] == "aa:bb:cc:dd:ee:ff"
        assert result[0]["network_yaml"] == "yaml2"

    def test_remove_nonexistent_host_config(self):
        """Test removing a host configuration that doesn't exist."""
        existing_config = json.dumps(
            [
                {
                    "mac_interface_map": [
                        {
                            "logical_nic_name": "eth0",
                            "mac_address": "00:11:22:33:44:55",
                        }
                    ],
                    "network_yaml": "yaml1",
                }
            ]
        )

        with pytest.raises(
            ValueError,
            match="host config for mac address ff:ff:ff:ff:ff:ff does not exist",
        ):
            remove_static_host_config(
                existing_static_network_config=existing_config,
                mac_address="ff:ff:ff:ff:ff:ff",
            )

    def test_remove_from_empty_config(self):
        """Test removing from an empty or None configuration."""
        with pytest.raises(
            ValueError,
            match="host config for mac address 00:11:22:33:44:55 does not exist",
        ):
            remove_static_host_config(
                existing_static_network_config=None,
                mac_address="00:11:22:33:44:55",
            )

    def test_remove_last_host_config(self):
        """Test removing the last host configuration from the list."""
        existing_config = json.dumps(
            [
                {
                    "mac_interface_map": [
                        {
                            "logical_nic_name": "eth0",
                            "mac_address": "00:11:22:33:44:55",
                        }
                    ],
                    "network_yaml": "yaml1",
                }
            ]
        )

        result = remove_static_host_config(
            existing_static_network_config=existing_config,
            mac_address="00:11:22:33:44:55",
        )

        assert len(result) == 0

    def test_handle_invalid_json_config_in_remove(self):
        """Test handling of invalid JSON in existing config during removal."""
        with pytest.raises(json.JSONDecodeError):
            remove_static_host_config(
                existing_static_network_config="invalid json",
                mac_address="00:11:22:33:44:55",
            )
