"""nmstate yaml templating logic"""

from typing import Any, Literal
from ipaddress import IPv4Address

from pydantic import BaseModel, Field
from jinja2 import Template
import yaml


class RouteParams(BaseModel):
    """The routes config in nmstate yaml"""

    destination: str = Field(
        "0.0.0.0/0", description="The destination addreses for which this route applies"
    )
    next_hop_address: str = Field(
        description="The IP address to which to route traffic for this route"
    )
    next_hop_interface: str = Field(
        description="The interface name over which traffic should be routed"
    )
    table_id: int | None = Field(
        254, description="The routing table id to add this route to"
    )
    metric: int | None = Field(None, description="The route metric value")


class IPV4AddressWithSubnet(BaseModel):
    """IPv4 address config for nmstate yaml"""

    address: IPv4Address
    cidr_length: int = Field(ge=0, le=32)


class EthernetInterfaceParams(BaseModel):
    """Ethernet interface config for nmstate yaml"""

    mac_address: str
    name: str = Field(
        description="Use a unique name like eth0, eth1, etc. if the user doesn't supply it"
    )
    ipv4_address: IPV4AddressWithSubnet | None = None


class BondInterfaceParams(BaseModel):
    """Bond interface config for nmstate yaml"""

    name: str = Field(
        description="Use a unique name like bond0, bond1, etc. if the user doesn't supply it"
    )
    ipv4_address: IPV4AddressWithSubnet | None = Field(
        None,
        description="The port interfaces should not have IP addresses configured on them, only the bond interface.",
    )
    mode: Literal[
        "balance-rr",
        "active-backup",
        "balance-xor",
        "broadcast",
        "802.3ad",
        "balance-tlb",
        "balance-alb",
    ] = "active-backup"
    port_interface_names: list[str] = Field(
        description="The interface names that are aggregated for this bond."
    )
    options: dict[str, Any] | None = Field(
        None, description="Link aggregation options for the bond interface"
    )


class VLANInterfaceParams(BaseModel):
    """VLAN config for nmstate yaml"""

    name: str = Field(
        description="Use a unique name like vlan0, vlan1, etc. if the user doesn't supply it"
    )
    ipv4_address: IPV4AddressWithSubnet | None = Field(
        None,
        description="If the user supplies an IP address for the vlan interface, don't reuse that same address on the base ethernet interface",
    )
    vlan_id: int
    base_interface_name: str = Field(
        description="If there is only one other ethernet interface configured for this host, use that interface name. Generally this base interface will not have an ip address configured, only the vlan interface."
    )


class DNSParams(BaseModel):
    """DNS config for nmstate yaml"""

    dns_servers: list[str] = Field(
        min_length=1, description="A list of DNS server IP addresses"
    )
    dns_search_domains: list[str] | None = Field(
        None, description="An optional list of DNS search domain names"
    )


class NMStateTemplateParams(BaseModel):
    """Top level params for generating nmstate yaml"""

    dns: DNSParams | None = None
    routes: list[RouteParams] | None = Field(
        None, description="A list of route table rules"
    )
    bond_ifaces: list[BondInterfaceParams] | None = Field(
        None, description="Configuration for bonded interfaces"
    )
    vlan_ifaces: list[VLANInterfaceParams] | None = Field(
        None, description="Configuration of vlan interfaces"
    )
    ethernet_ifaces: list[EthernetInterfaceParams] = Field(
        min_length=1,
        description="List of the ethernet interfaces on the machine, at least one is required.",
    )


def generate_nmstate_from_template(params: NMStateTemplateParams) -> str:
    """Generate the nmstate yaml based on the params"""
    # Go through a serialization loop to standardize indentation and whitespace.
    return yaml.dump(yaml.safe_load(NMSTATE_TEMPLATE.render(params)))


NMSTATE_TEMPLATE = Template(
    """
{% if dns %}
dns-resolver:
  config:
    server:
    {% for s in dns.dns_servers %}
    - {{ s }}
    {% endfor %}
    {% if dns.dns_search_domains %}
    search:
    {% for d in dns.dns_search_domains %}
    - {{ d }}
    {% endfor %}
    {% endif %}
{% endif %}
{% if routes %}
routes:
  config:
  {% for r in routes %}
    - destination: {{r.destination}}
      next-hop-address: {{r.next_hop_address}}
      next-hop-interface: {{r.next_hop_interface}}
      {% if r.table_id is not none %}
      table-id: {{r.table_id}}
      {% endif %}
      {% if r.metric is not none %}
      metric: {{r.metric}}
      {% endif %}
  {% endfor %}
{% endif %}
interfaces:
{% for i in ethernet_ifaces %}
- name: {{i.name}}
  type: ethernet
  state: up
  mac-address: {{i.mac_address}}
  ipv4:
  {% if i.ipv4_address %}
    address:
    - ip: {{i.ipv4_address.address}}
      prefix-length: {{i.ipv4_address.cidr_length}}
    enabled: true
  {% else %}
    enabled: false
  {% endif %}
    dhcp: false
  ipv6:
    enabled: false
{% endfor %}
{% if vlan_ifaces %}
{% for i in vlan_ifaces %}
- name: {{i.name}}
  type: vlan
  state: up
  ipv4:
  {% if i.ipv4_address %}
    address:
    - ip: {{i.ipv4_address.address}}
      prefix-length: {{i.ipv4_address.cidr_length}}
    enabled: true
  {% else %}
    enabled: false
  {% endif %}
    dhcp: false
  ipv6:
    enabled: false
  vlan:
    base-iface: {{i.base_interface_name}}
    id: {{i.vlan_id}}
{% endfor %}
{% endif %}
{% if bond_ifaces %}
{% for i in bond_ifaces %}
- name: {{i.name}}
  type: bond
  state: up
  ipv4:
  {% if i.ipv4_address %}
    address:
    - ip: {{i.ipv4_address.address}}
      prefix-length: {{i.ipv4_address.cidr_length}}
    enabled: true
  {% else %}
    enabled: false
  {% endif %}
    dhcp: false
  ipv6:
    enabled: false
  link-aggregation:
    mode: {{i.mode}}
    port: 
    {% for p in i.port_interface_names %}
    - {{p}}
    {% endfor %}
    {% if i.options %}
    options:
    {% for k, v in i.options.items() %}
      {{k}}: {{v}} 
    {% endfor %}
    {% endif %}
{% endfor %}
{% endif %}
"""
)
