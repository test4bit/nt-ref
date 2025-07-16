# gh_runner_service/services/xray_direct.py
import json
import logging
import time
from datetime import timedelta  
from pathlib import Path
from typing import cast

from ..common.exceptions import AppError
from ..common.models import ClientInfo, XrayConfig, XrayVlessOutbound
from ..common.utils import manage_process, run_command


def setup_service(client: ClientInfo, uuid: str, base_dir: Path, config_dir: Path) -> None:
    """
    Configures and runs an Xray reverse tunnel that routes traffic
    directly to the internet via the 'freedom' protocol.
    """
    logging.info("Setting up Xray server in DIRECT (Freedom) mode.")
    _ = run_command("sysctl -w net.core.default_qdisc=fq", check=False)
    _ = run_command("sysctl -w net.ipv4.tcp_congestion_control=bbr", check=False)

    config_path = config_dir / "bridge_direct_freedom.json"
    if not config_path.exists():
        raise AppError(f"Direct Freedom Xray config not found: {config_path}")

    with open(config_path) as f:
        xray_config = cast(XrayConfig, json.load(f))

    vless_found = False
    for outbound in xray_config["outbounds"]:
        if outbound["protocol"] == "vless":
            vless_outbound = cast(XrayVlessOutbound, outbound)
            vless_outbound["settings"]["vnext"][0]["address"] = client.ip
            vless_outbound["settings"]["vnext"][0]["users"][0]["id"] = uuid
            vless_found = True
            break

    if not vless_found:
        raise AppError("Could not find a VLESS outbound in bridge_direct_freedom.json")

    final_config_path = base_dir / "bridge-final.json"
    with open(final_config_path, "w") as f:
        json.dump(xray_config, f, indent=2)

    logging.info("Direct Xray (Freedom) configuration generated successfully.")
    xray_executable_path = base_dir / "bin/xray"
    command = f"{xray_executable_path} run -c {final_config_path}"

    with manage_process(command) as process:
        time.sleep(1)
        if process.poll() is not None:
            raise AppError(f"Xray failed to start. Exit code: {process.returncode}")

        sleep_duration = timedelta(hours=5, minutes=59, seconds=50)
        logging.info(f"Service running. Sleeping for {sleep_duration} before shutdown...")
        time.sleep(sleep_duration.total_seconds())

    logging.info("Direct service operation concluded.")
