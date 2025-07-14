# gh_runner_service/services/xray_direct.py
import json
import logging
from pathlib import Path
from typing import cast

from ..common.exceptions import AppError
from ..common.models import (
    ClientInfo,
    XrayConfig,
    XrayVlessOutbound,
)
from ..common.utils import run_command

def setup_service(client: ClientInfo, uuid: str, base_dir: Path, config_dir: Path) -> None:
    """
    Configures and runs an Xray reverse tunnel that routes traffic
    directly to the internet via the 'freedom' protocol.
    """
    logging.info("Setting up Xray server in DIRECT (Freedom) mode.")
    # BBR commands are good practice for network performance.
    _ = run_command("sysctl -w net.core.default_qdisc=fq")
    _ = run_command("sysctl -w net.ipv4.tcp_congestion_control=bbr")

    # Load the new config file specifically designed for this mode.
    config_path = config_dir / "bridge_direct_freedom.json"
    if not config_path.exists():
        raise AppError(f"Direct Freedom Xray config not found: {config_path}")

    with open(config_path) as f:
        xray_config = cast(XrayConfig, json.load(f))

    # This logic is essential: we must configure the VLESS client within Xray
    # to connect back to the user's VLESS server.
    vless_found = False
    for outbound in xray_config["outbounds"]:
        if outbound["protocol"] == "vless":
            vless_outbound = cast(XrayVlessOutbound, outbound)
            # Set the user's VLESS server IP and authentication UUID.
            vless_outbound["settings"]["vnext"][0]["address"] = client.ip
            vless_outbound["settings"]["vnext"][0]["users"][0]["id"] = uuid
            vless_found = True
            break

    if not vless_found:
        raise AppError("Could not find a VLESS outbound to configure in bridge_direct_freedom.json")

    final_config_path = base_dir / "bridge-final.json"
    with open(final_config_path, "w") as f:
        json.dump(xray_config, f, indent=2)

    logging.info("Direct Xray (Freedom) configuration generated successfully.")
    xray_executable_path = base_dir / "bin/xray"
    _ = run_command(f"{xray_executable_path} run -c {final_config_path}")
    _ = run_command("sleep 365d")
