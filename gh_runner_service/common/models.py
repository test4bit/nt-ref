# gh_runner_service/common/models.py
from dataclasses import dataclass
from typing import NotRequired, TypedDict

# --- Dataclass for Client Info ---
@dataclass
class ClientInfo:
    """Holds information about the connecting client."""
    ip: str
    port: int
    local_port: int | None = None

# --- Dataclass for WARP API data ---
@dataclass
class WarpConfig:
    """A dataclass to hold the final, formatted WARP configuration."""
    endpoint_v4: str
    private_key: str
    public_key: str
    address_v4: str
    reserved_dec: list[int]


# --- Type Definitions for the direct.json config ---

class XrayDirectClient(TypedDict):
    id: str
    # Add other client keys if they exist, e.g., flow: str

class XrayDirectSettings(TypedDict):
    clients: list[XrayDirectClient]
    # Add other settings keys if they exist

class XrayDirectInbound(TypedDict):
    # Add all keys for an inbound block
    protocol: str
    port: int
    listen: str
    settings: XrayDirectSettings
    # ... etc

class XrayDirectConfig(TypedDict):
    # Add all top-level keys
    log: dict[str, str]
    inbounds: list[XrayDirectInbound]
    outbounds: list[dict[str, str]] # A simple outbound for direct mode

# --- Type Definitions for Xray JSON config ---
# These are the granular building blocks for the outbound types.


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

class XrayRealitySettings(TypedDict):
    fingerprint: str
    serverName: str
    publicKey: str
    spiderX: str
    shortId: str

class XrayStreamSettings(TypedDict):
    network: str
    security: str
    realitySettings: XrayRealitySettings

# --- Define specific, independent TypedDicts for each outbound type ---
# This avoids the incompatible override error and is more robust.

class XrayVlessOutbound(TypedDict):
    """A precisely typed VLESS outbound."""
    protocol: str
    tag: str
    settings: XrayVlessSettings
    streamSettings: XrayStreamSettings

class XrayWireguardOutbound(TypedDict):
    """A precisely typed WireGuard outbound."""
    protocol: str
    tag: str
    settings: XrayWgSettings

class XrayOtherOutbound(TypedDict):
    """A catch-all for outbounds we don't need to inspect deeply."""
    protocol: str
    tag: str
    # Use `dict[str, object]` as a safer alternative to `dict[str, Any]`
    settings: NotRequired[dict[str, object]]

# The final Outbound type is a union of all possible specific types,
# using the modern `|` syntax.
Outbound = XrayVlessOutbound | XrayWireguardOutbound | XrayOtherOutbound

class XrayConfig(TypedDict):
    outbounds: list[Outbound]
