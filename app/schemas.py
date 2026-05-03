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
