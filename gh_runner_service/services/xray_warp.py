# gh_runner_service/services/xray_warp.py
import json
import logging
from pathlib import Path
from typing import cast

from ..common.exceptions import AppError
from ..common.models import (
    ClientInfo,
    XrayConfig,
    XrayVlessOutbound,
    XrayWireguardOutbound,
)
from ..common.utils import run_command
from .cloudflare_warp import get_warp_config

def setup_service(client: ClientInfo, uuid: str, base_dir: Path, config_dir: Path) -> None:
    """Configures and runs the Xray server with WARP."""
    logging.info("Setting up Xray server with WARP.")
    _ = run_command("sysctl -w net.core.default_qdisc=fq")
    _ = run_command("sysctl -w net.ipv4.tcp_congestion_control=bbr")

    warp_config = get_warp_config()

    config_path = config_dir / "bridge_with_warp.json"
    if not config_path.exists():
        raise AppError(f"WARP Xray config not found: {config_path}")

    with open(config_path) as f:
        xray_config = cast(XrayConfig, json.load(f))

    for outbound in xray_config["outbounds"]:
        if outbound["protocol"] == "vless":
            vless_outbound = cast(XrayVlessOutbound, outbound)
            vless_outbound["settings"]["vnext"][0]["address"] = client.ip
            vless_outbound["settings"]["vnext"][0]["users"][0]["id"] = uuid
        elif outbound["protocol"] == "wireguard":
            wg_outbound = cast(XrayWireguardOutbound, outbound)
            wg_outbound["settings"]["secretKey"] = warp_config.private_key
            wg_outbound["settings"]["address"] = [warp_config.address_v4]
            wg_outbound["settings"]["peers"][0]["publicKey"] = warp_config.public_key
            wg_outbound["settings"]["peers"][0]["endpoint"] = warp_config.endpoint_v4
            wg_outbound["settings"]["reserved"] = warp_config.reserved_dec

    final_config_path = base_dir / "bridge-final.json"
    with open(final_config_path, "w") as f:
        json.dump(xray_config, f, indent=2)

    logging.info("Xray+WARP configuration generated successfully.")
    xray_executable_path = base_dir / "bin/xray"
    _ = run_command(f"{xray_executable_path} run -c {final_config_path}")
    _ = run_command("sleep 365d")
