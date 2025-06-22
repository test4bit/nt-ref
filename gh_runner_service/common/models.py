# gh_runner_service/models.py
from dataclasses import dataclass
from typing import Any, TypedDict

# --- Dataclass for Client Info ---
@dataclass
class ClientInfo:
    """Holds information about the connecting client."""
    ip: str
    port: int
    local_port: int | None = None

# --- Type Definitions for WARP API data ---
@dataclass
class WarpConfig:
    """A dataclass to hold the final, formatted WARP configuration."""
    endpoint_v4: str
    private_key: str
    public_key: str
    address_v4: str
    reserved_dec: list[int]

# --- Type Definitions for Xray JSON config ---
class XrayWgPeer(TypedDict):
    publicKey: str
    endpoint: str

class XrayWgSettings(TypedDict):
    secretKey: str
    address: list[str]
    peers: list[XrayWgPeer]
    reserved: list[int]

class XrayVlessUser(TypedDict):
    id: str

class XrayVlessVnext(TypedDict):
    address: str
    users: list[XrayVlessUser]

class XrayVlessSettings(TypedDict):
    vnext: list[XrayVlessVnext]

Outbound = dict[str, Any]

class XrayConfig(TypedDict):
    outbounds: list[Outbound]
