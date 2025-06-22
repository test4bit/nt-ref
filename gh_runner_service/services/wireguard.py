# gh_runner_service/services/wireguard.py
import configparser
import logging
import re
from pathlib import Path

from ..common.utils import run_command
from ..common.exceptions import AppError
from ..models import ClientInfo

# Constants
STUN_SERVER = "stun.l.google.com:19302"
WG_SERVER_PORT = 443
WG_SERVER_IP = "192.168.166.1"
WG_CLIENT_IP = "192.168.166.2"

def setup_client_mode(client: ClientInfo, private_key: str, base_dir: Path, config_dir: Path) -> None:
    """Configures the Action as a WireGuard CLIENT connecting OUT to the user."""
    logging.info("Setting up WireGuard in CLIENT mode (direct-connect).")
    config = configparser.ConfigParser()
    template_path = config_dir / "wg_client.conf"
    if not template_path.exists():
        raise AppError(f"Client config template not found: {template_path}")
    config.read(template_path)

    config["Interface"]["PrivateKey"] = private_key
    config["Peer"]["Endpoint"] = f"{client.ip}:{client.port}"

    final_config_path = base_dir / "wg0-final.conf"
    with open(final_config_path, "w") as f:
        config.write(f)
    logging.info(f"Final client config written to {final_config_path}")

    run_command("sudo ip link add dev wg0 type wireguard")
    run_command(f"sudo wg setconf wg0 {final_config_path}")
    run_command(f"sudo ip address add dev wg0 {WG_SERVER_IP}/30")
    run_command(f"sudo ip link set up dev wg0")
    run_command("sudo iptables -A FORWARD -i wg0 -j ACCEPT")
    run_command("sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE")
    
    logging.info("WireGuard (Client) is up and running.")
    run_command("sleep 365d")

def setup_server_mode(client: ClientInfo, private_key: str, base_dir: Path, config_dir: Path) -> bool:
    """Configures the Action as a WireGuard SERVER listening for the user (hole-punch)."""
    logging.info("Setting up WireGuard in SERVER mode (hole-punch).")
    config = configparser.ConfigParser()
    template_path = config_dir / "wg_server.conf"
    if not template_path.exists():
        raise AppError(f"Server config template not found: {template_path}")
    config.read(template_path)

    config["Interface"]["PrivateKey"] = private_key

    final_config_path = base_dir / "wg0-final.conf"
    with open(final_config_path, "w") as f:
        config.write(f)
    logging.info(f"Final server config written to {final_config_path}")

    logging.info("Detecting server's external IP and port mapping via STUN...")
    stun_cmd = f"sudo stun -v {STUN_SERVER} -p {WG_SERVER_PORT}"
    result = run_command(stun_cmd)
    output = result.stdout + result.stderr
    mapped_addr_match = re.search(r"MappedAddress.*?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)", output)
    if not mapped_addr_match:
        raise AppError("Could not determine server's external mapping via STUN.")
    server_ext_ip, server_ext_port = mapped_addr_match.groups()
    logging.info(f"Server mapped to {server_ext_ip}:{server_ext_port}")

    logging.info(f"Starting NAT punch towards client at {client.ip}:{client.port}")
    punch_cmd = (f"while true; do "
                 f"echo -n 'punch' | sudo nc -u -p {WG_SERVER_PORT} {client.ip} {client.port}; "
                 f"sleep 25; "
                 f"done &")
    run_command(punch_cmd)

    user_client_config = f"""[Interface]
ListenPort = {client.local_port}
Address = {WG_CLIENT_IP}/30
PrivateKey = <YOUR_CLIENT_PRIVATE_KEY_NEEDS_TO_BE_GENERATED>

[Peer]
PublicKey = {config['Peer']['PublicKey']}
Endpoint = {server_ext_ip}:{server_ext_port}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
"""
    artifact_path = base_dir / "wg_user.conf"
    with open(artifact_path, "w") as f:
        f.write(user_client_config)
    logging.info(f"User client configuration saved to {artifact_path} for artifact upload.")

    run_command("sudo ip link add dev wg0 type wireguard")
    run_command(f"sudo wg setconf wg0 {final_config_path}")
    run_command(f"sudo ip address add dev wg0 {WG_SERVER_IP}/30")
    run_command(f"sudo ip link set up dev wg0")
    run_command("sudo iptables -A FORWARD -i wg0 -j ACCEPT")
    run_command("sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE")
    
    logging.info("WireGuard (Server) is up and running.")
    return True
