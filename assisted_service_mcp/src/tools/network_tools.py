"""Network configuration tools for Assisted Service MCP Server."""

import json
from typing import Annotated, Callable
from pydantic import Field
from jinja2 import TemplateError

from assisted_service_mcp.src.metrics import track_tool_usage
from assisted_service_mcp.src.service_client.assisted_service_api import InventoryClient
from assisted_service_mcp.src.logger import log
from assisted_service_mcp.src.utils.static_net import (
    NMStateTemplateParams,
    add_or_replace_static_host_config_yaml,
    generate_nmstate_from_template,
    remove_static_host_config_by_index,
    validate_and_parse_nmstate,
)
from assisted_service_mcp.src.tools.shared_helpers import _get_cluster_infra_env_id


@track_tool_usage()
async def validate_nmstate_yaml(
    _get_access_token_func: Callable[[], str],
    nmstate_yaml: Annotated[
        str,
        Field(
            description="The NMState YAML document to validate. This defines static network configuration for a host."
        ),
    ],
) -> str:
    r"""Validate an NMState YAML document before applying to hosts.

    Validates the YAML syntax and structure to ensure it's correct before submitting to the
    cluster. Always validate YAML after generating or manually editing before applying it to
    hosts. Invalid YAML will cause host configuration failures.

    Prerequisites:
        - NMState YAML document (from generate_nmstate_yaml or manual creation)

    Related tools:
        - generate_nmstate_yaml - Generate initial YAML from parameters
        - alter_static_network_config_nmstate_for_host - Apply validated YAML to hosts
        - list_static_network_config - View currently applied configurations

    Returns:
        str: "YAML is valid" if successful, otherwise error message.
    """
    validate_and_parse_nmstate(nmstate_yaml)
    return "YAML is valid"


@track_tool_usage()
async def generate_nmstate_yaml(
    _get_access_token_func: Callable[[], str],
    params: Annotated[
        NMStateTemplateParams,
        Field(
            description="Structured network configuration parameters including interface name, IP addresses (IPv4/IPv6), DNS servers, gateway, and routes. Use NMStateTemplateParams schema."
        ),
    ],
) -> str:
    """Generate NMState YAML from structured network parameters.

    Creates NMState YAML configuration from structured parameters rather than writing YAML
    manually. Always use this to generate initial YAML from user requirements, then validate
    and optionally tweak the result. Do not generate nmstate yaml from scratch without calling
    this tool.

    Prerequisites:
        - Network information from user (interface, IPs, gateway, DNS)

    Related tools:
        - validate_nmstate_yaml - Validate the generated YAML
        - alter_static_network_config_nmstate_for_host - Apply generated YAML to hosts
        - list_static_network_config - View applied configurations

    Returns:
        str: Generated nmstate YAML or error message.
    """
    log.info("Generate nmstate yaml with params: %s", params.model_dump_json(indent=2))
    try:
        generated = generate_nmstate_from_template(params)
        log.debug("Generated yaml: %s", generated)
        return generated
    except TemplateError as e:
        log.error("Failed to render nmstate template", exc_info=e)
        return "ERROR: Failed to generate nmstate yaml"
    except Exception as e:
        log.error("Exception generating nmstate yaml", exc_info=e)
        return "ERROR: Unknown error"


@track_tool_usage()
async def alter_static_network_config_nmstate_for_host(
    get_access_token_func: Callable[[], str],
    cluster_id: Annotated[
        str,
        Field(description="The unique identifier of the cluster to configure."),
    ],
    index: Annotated[
        int | None,
        Field(
            description="The position of the host in the static network configuration list. Use None to append a new host configuration. Use 0, 1, 2, etc. to replace or delete an existing host configuration."
        ),
    ],
    new_nmstate_yaml: Annotated[
        str | None,
        Field(
            description="The validated NMState YAML to apply. Use None to delete the configuration at the specified index. Provide YAML to add or update a configuration."
        ),
    ],
) -> str:
    r"""Add, replace, or delete static network configuration for a host.

    Manages static network configurations for cluster hosts. To add a new host config, use
    index=None and provide YAML. To update an existing host config, provide the index and
    new YAML. To remove a host config, provide the index and set YAML=None. Each
    configuration corresponds to one host in the order they boot from the ISO.

    Examples:
        - alter_static_network_config_nmstate_for_host("cluster-uuid", None, "interfaces:\\n- name: eth0...")  # Add new host config
        - alter_static_network_config_nmstate_for_host("cluster-uuid", 0, "interfaces:\\n- name: eth1...")  # Update first host
        - alter_static_network_config_nmstate_for_host("cluster-uuid", 1, None)  # Delete second host config

    Prerequisites:
        - Valid OCM offline token for authentication
        - Validated NMState YAML (from validate_nmstate_yaml)
        - Cluster with infrastructure environment
        - Know which host corresponds to which index (first boot = index 0, second = 1, etc.)

    Related tools:
        - generate_nmstate_yaml - Create YAML from parameters
        - validate_nmstate_yaml - Validate YAML before applying
        - list_static_network_config - View current configurations and indices
        - cluster_info - View cluster and infrastructure environment

    Returns:
        str: Updated infrastructure environment with new static network config.
    """
    client = InventoryClient(get_access_token_func())
    infra_env_id = await _get_cluster_infra_env_id(client, cluster_id)
    infra_env = await client.get_infra_env(infra_env_id)

    if new_nmstate_yaml is None:
        if index is None:
            raise ValueError("index cannot be null when removing a host yaml")
        if not infra_env.static_network_config:
            raise ValueError(
                "cannot remove host yaml with empty existing static network config"
            )
        static_network_config = remove_static_host_config_by_index(
            existing_static_network_config=infra_env.static_network_config, index=index
        )
    else:
        static_network_config = add_or_replace_static_host_config_yaml(
            existing_static_network_config=infra_env.static_network_config,
            index=index,
            new_nmstate_yaml=new_nmstate_yaml,
        )

    result = await client.update_infra_env(
        infra_env_id, static_network_config=static_network_config
    )
    return result.to_str()


@track_tool_usage()
async def list_static_network_config(
    get_access_token_func: Callable[[], str],
    cluster_id: Annotated[
        str,
        Field(description="The unique identifier of the cluster to query."),
    ],
) -> str:
    """List all static network configurations for cluster hosts.

    Shows all static network configurations applied to the cluster's infrastructure
    environment. Each configuration in the array corresponds to one host, in the order
    they were added. Use the array index when updating or deleting specific host
    configurations.

    Prerequisites:
        - Cluster with infrastructure environment

    Related tools:
        - alter_static_network_config_nmstate_for_host - Add, update, or remove configs
        - generate_nmstate_yaml - Generate new configurations
        - validate_nmstate_yaml - Validate configurations
        - cluster_info - View cluster and infrastructure environment details

    Returns:
        str: JSON array of static network configs, or error message.
    """
    client = InventoryClient(get_access_token_func())
    infra_envs = await client.list_infra_envs(cluster_id)
    log.info("Found %d InfraEnvs for cluster %s", len(infra_envs), cluster_id)

    if len(infra_envs) != 1:
        log.warning(
            "cluster %s has %d infra_envs, expected 1", cluster_id, len(infra_envs)
        )
        return "ERROR: this cluster doesn't have exactly 1 infra env, cannot manage static network config"

    return json.dumps(infra_envs[0].get("static_network_config", []))
