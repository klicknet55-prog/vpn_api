from ipaddress import IPv4Address

from pydantic import BaseModel, Field


class UserCreateRequest(BaseModel):
    username: str = Field(min_length=3, max_length=32)
    password: str = Field(min_length=4, max_length=128)
    ip: IPv4Address


class MessageResponse(BaseModel):
    message: str


class DisconnectResponse(BaseModel):
    message: str
    disconnected_sessions: int


class PortForwardCreateRequest(BaseModel):
    name: str = Field(min_length=3, max_length=64)
    protocol: str = Field(pattern=r"^(tcp|udp)$")
    listen_port: int = Field(ge=1, le=65535)
    destination_ip: IPv4Address
    destination_port: int = Field(ge=1, le=65535)


class PortForwardRule(BaseModel):
    name: str
    protocol: str
    listen_port: int
    destination_ip: str
    destination_port: int
    created_at: str


class ProxyRouteCreateRequest(BaseModel):
    name: str = Field(min_length=3, max_length=64)
    subdomain: str = Field(pattern=r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
    port_forward_name: str = Field(min_length=3, max_length=64)


class ProxyRoute(BaseModel):
    name: str
    subdomain: str
    domain: str
    port_forward_name: str
    upstream_ip: str
    upstream_port: int
    ssl_enabled: bool
    created_at: str


class SubdomainAvailability(BaseModel):
    subdomain: str
    domain: str
    available: bool
    exists_in_db: bool
    exists_in_dns: bool
    dns_checked: bool
    dns_records: list[str]
    reason: str
