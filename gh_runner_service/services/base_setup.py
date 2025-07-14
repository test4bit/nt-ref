# gh_runner_service/services/base_setup.py
import logging
from pathlib import Path

from ..common.utils import run_command

def setup_common_environment(base_dir: Path) -> None:
    """Sets up SSH keys and IP forwarding."""
    logging.info("Configuring common environment settings.")
    auth_keys_file = base_dir / "authorized_keys"
    if auth_keys_file.exists():
        _ = run_command(f"mkdir -p /root/.ssh && cp {auth_keys_file} /root/.ssh/authorized_keys")
    _ = run_command("sysctl -w net.ipv4.ip_forward=1")
