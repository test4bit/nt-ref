# gh_runner_service/services/xray_direct.py
import json
import logging
from pathlib import Path

from ..common.utils import run_command
from ..common.exceptions import AppError
from ..models import ClientInfo

def setup_service(client: ClientInfo, uuid: str, base_dir: Path, config_dir: Path) -> None:
    """Configures and runs a direct-connection Xray server (no WARP)."""
    logging.info("Setting up Xray server in DIRECT mode.")
    run_command("sudo sysctl -w net.core.default_qdisc=fq")
    run_command("sudo sysctl -w net.ipv4.tcp_congestion_control=bbr")

    config_path = config_dir / "direct.json"
    if not config_path.exists():
        raise AppError(f"Direct Xray config not found: {config_path}")
    with open(config_path) as f:
        xray_config = json.load(f)

    xray_config["inbounds"][0]["settings"]["clients"][0]["id"] = uuid

    run_command("sudo openssl ecparam -genkey -name prime256v1 -out /etc/ssl/private/xray.key")
    run_command(f"sudo openssl req -new -x509 -days 365 -key /etc/ssl/private/xray.key -out /etc/ssl/certs/xray.crt -subj '/CN={client.ip}'")

    final_config_path = base_dir / "bridge-final.json"
    with open(final_config_path, "w") as f:
        json.dump(xray_config, f, indent=2)
    
    logging.info("Direct Xray configuration generated successfully.")
    xray_executable_path = base_dir / "bin/xray"
    run_command(f"sudo {xray_executable_path} run -c {final_config_path}")
    run_command("sleep 365d")
