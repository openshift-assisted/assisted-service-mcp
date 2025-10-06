"""Network configuration tools for Assisted Service MCP Server."""

import json
from jinja2 import TemplateError

from metrics import track_tool_usage
from assisted_service_mcp.utils.client_factory import InventoryClient
from service_client.logger import log
from static_net import (
    NMStateTemplateParams,
    add_or_replace_static_host_config_yaml,
    generate_nmstate_from_template,
    remove_static_host_config_by_index,
    validate_and_parse_nmstate,
)
from assisted_service_mcp.src.tools.shared_helpers import _get_cluster_infra_env_id


@track_tool_usage()
async def validate_nmstate_yaml(mcp, get_access_token_func, nmstate_yaml: str) -> str:
    """Validate an nmstate YAML document before submission.

    TOOL_NAME=validate_nmstate_yaml
    DISPLAY_NAME=Validate NMState YAML
    USECASE=Validate static network configuration YAML before applying to hosts
    INSTRUCTIONS=1. Generate or obtain nmstate YAML, 2. Call function to validate, 3. Fix errors if validation fails, 4. Apply to hosts after validation succeeds
    INPUT_DESCRIPTION=nmstate_yaml (string): NMState YAML document for static network configuration
    OUTPUT_DESCRIPTION=String "YAML is valid" on success, or error message with validation failure details
    EXAMPLES=validate_nmstate_yaml("interfaces:\\n- name: eth0\\n  type: ethernet\\n  state: up")
    PREREQUISITES=NMState YAML document (from generate_nmstate_yaml or manually created)
    RELATED_TOOLS=generate_nmstate_yaml (generate initial YAML), alter_static_network_config_nmstate_for_host (apply validated YAML)

    CPU-bound operation - uses def for validation logic.

    The YAML must be validated before being submitted to the cluster to ensure correct network configuration.

    Args:
        nmstate_yaml (str): The nmstate YAML to validate.

    Returns:
        str: "YAML is valid" if successful, otherwise error message.
    """
    validate_and_parse_nmstate(nmstate_yaml)
    return "YAML is valid"


@track_tool_usage()
async def generate_nmstate_yaml(
    mcp, get_access_token_func, params: NMStateTemplateParams
) -> str:
    """Generate initial nmstate YAML from network configuration parameters.

    TOOL_NAME=generate_nmstate_yaml
    DISPLAY_NAME=Generate NMState YAML
    USECASE=Generate initial static network configuration YAML from structured parameters
    INSTRUCTIONS=1. Gather network info from user (interface, IPs, DNS, gateway), 2. Call with NMStateTemplateParams, 3. Receive generated YAML, 4. Validate with validate_nmstate_yaml, 5. Apply with alter_static_network_config_nmstate_for_host
    INPUT_DESCRIPTION=params (NMStateTemplateParams): structured network configuration including interface name, IP addresses, DNS servers, gateway, routes
    OUTPUT_DESCRIPTION=Generated nmstate YAML string, or error message if generation fails
    EXAMPLES=generate_nmstate_yaml(NMStateTemplateParams(interface_name="eth0", ipv4_address="192.168.1.10/24", ipv4_gateway="192.168.1.1"))
    PREREQUISITES=Network configuration information from user
    RELATED_TOOLS=validate_nmstate_yaml (validate generated YAML), alter_static_network_config_nmstate_for_host (apply to host)

    I/O-bound operation - uses async def for potential future API calls.

    Always use this tool to generate initial YAML from user input rather than creating YAML from scratch.
    The generated YAML can be tweaked as needed before validation and application.

    Args:
        params: NMStateTemplateParams object containing network configuration.

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
    mcp,
    get_access_token_func,
    cluster_id: str,
    index: int | None,
    new_nmstate_yaml: str | None,
) -> str:
    """Add, replace, or delete nmstate YAML configuration for a specific host.

    TOOL_NAME=alter_static_network_config_nmstate_for_host
    DISPLAY_NAME=Alter Host Static Network Config
    USECASE=Apply, update, or remove static network configuration for individual cluster hosts
    INSTRUCTIONS=1. Generate/validate YAML, 2. Get cluster_id, 3. To add: set index=None, provide YAML, 4. To update: set index to host position, provide new YAML, 5. To remove: set index to host position, set YAML=None
    INPUT_DESCRIPTION=cluster_id (string): cluster UUID, index (int or null): host position in config list (null to append new), new_nmstate_yaml (string or null): validated nmstate YAML (null to delete config at index)
    OUTPUT_DESCRIPTION=Formatted string with updated infrastructure environment showing new static network configuration
    EXAMPLES=alter_static_network_config_nmstate_for_host("cluster-uuid", None, "interfaces:\\n- name: eth0..."), alter_static_network_config_nmstate_for_host("cluster-uuid", 0, None)
    PREREQUISITES=Validated nmstate YAML (from validate_nmstate_yaml), cluster with infrastructure environment
    RELATED_TOOLS=generate_nmstate_yaml (generate YAML), validate_nmstate_yaml (validate before applying), list_static_network_config (view current configs)

    I/O-bound operation - uses async def for external API calls.

    Add new host: index=None, provide YAML (appends to end).
    Replace host config: provide index and new YAML.
    Delete host config: provide index, set YAML=None.

    Args:
        cluster_id (str): The unique identifier of the cluster.
        index (int | None): Host position in config list, or None to append.
        new_nmstate_yaml (str | None): New nmstate YAML, or None to delete.

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
    mcp, get_access_token_func, cluster_id: str
) -> str:
    """List all host static network configurations for a cluster.

    TOOL_NAME=list_static_network_config
    DISPLAY_NAME=List Static Network Configs
    USECASE=View all static network configurations applied to cluster hosts
    INSTRUCTIONS=1. Get cluster_id, 2. Call function, 3. Receive JSON array of host configs with indices
    INPUT_DESCRIPTION=cluster_id (string): cluster UUID
    OUTPUT_DESCRIPTION=JSON array of static network configurations (one per host), or error if cluster doesn't have exactly one infrastructure environment
    EXAMPLES=list_static_network_config("cluster-uuid")
    PREREQUISITES=Cluster with infrastructure environment
    RELATED_TOOLS=alter_static_network_config_nmstate_for_host (modify configs), generate_nmstate_yaml (create new configs), cluster_info

    I/O-bound operation - uses async def for external API calls.

    Returns all host static network configurations for the cluster's infrastructure environment.
    Each configuration corresponds to one host, indexed by position in the array.

    Args:
        cluster_id (str): The unique identifier of the cluster.

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

