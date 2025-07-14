#!/usr/bin/env python3
import argparse
import json
import logging
import os
import re
import shlex
import subprocess
import sys
import time
from pathlib import Path
from typing import cast

# This line is crucial for running the script directly.
sys.path.append(str(Path(__file__).resolve().parent.parent))

from gh_runner_service.common.crypto import encrypt_payload
from gh_runner_service.common.exceptions import AppError
from gh_runner_service.common.utils import check_dependencies, get_env_or_fail

LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)

ENCRYPTION_KEY_ENV_VAR = "GHA_PAYLOAD_KEY"
STUN_SERVER = "stun.l.google.com:19302"

def get_public_ip() -> str:
    """Fetches the public IP address."""
    logging.info("Fetching public IP address...")
    try:
        result = subprocess.run(
            ['curl', '-s', 'https://icanhazip.com'],
            capture_output=True, text=True, check=True, timeout=10
        )
        ip = result.stdout.strip()
        if not ip:
            raise AppError("Failed to get a valid public IP address.")
        logging.info(f"Detected public IP: {ip}")
        return ip
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        raise AppError(f"Could not fetch public IP: {e}")

def run_stun_client(local_port: int) -> tuple[str, str]:
    """Runs the STUN client to determine external IP and mapped port."""
    logging.info(f"Running STUN client on local port {local_port}...")
    stun_cmd = f"stun -v {STUN_SERVER} -p {local_port}"
    result = subprocess.run(shlex.split(stun_cmd), capture_output=True, text=True, timeout=15)
    output = result.stdout + result.stderr
    if result.returncode > 10 or not output.strip():
        raise AppError(f"STUN client execution failed. Exit Code: {result.returncode}")

    mapped_addr_match = re.search(r"MappedAddress = (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+)", output)
    nat_type_match = re.search(r"Primary: (.*)", output)
    if not mapped_addr_match or not nat_type_match:
        raise AppError("Could not parse STUN client output.")

    ipport = mapped_addr_match.group(1)
    nat_type = nat_type_match.group(1).strip()
    logging.info(f"STUN result: Mapped Address = {ipport}, NAT Type = {nat_type}")
    if "Independent Mapping" not in nat_type and "hole-punch" in sys.argv:
        raise AppError(f"Incompatible NAT type: '{nat_type}'.")
    return ipport, nat_type

def main() -> None:
    """Main entry point for the V2 client."""
    check_dependencies("git", "gh", "curl")

    parser = argparse.ArgumentParser(description="V2 Client for GitHub Actions NAT traversal.")
    _ = parser.add_argument(
        "mode",
        choices=["direct-connect", "hole-punch", "xray", "xray-direct"],
        help="The operational mode."
    )
    _ = parser.add_argument(
        "--repo",
        help="The GitHub repository in 'owner/repo' format. Defaults to GH_REPO env var."
    )
    args = parser.parse_args()
    mode = cast(str, args.mode)
    repo_arg: str | None = cast(str | None, args.repo)

    # FIX: Initialize variables to None before the try block.
    run_id: int | None = None
    repo: str | None = None

    try:
        encryption_key = get_env_or_fail(ENCRYPTION_KEY_ENV_VAR)
        repo = repo_arg or get_env_or_fail("GH_REPO")
        _ = get_env_or_fail("GITHUB_TOKEN")

        logging.info(f"Preparing to trigger V2 workflow in '{mode}' mode.")
        payload_str = ""
        if mode == "hole-punch":
            check_dependencies("stun", "nc")
            local_port = 20000 + (os.getpid() % 10000)
            ipport, _ = run_stun_client(local_port)
            payload_str = f"{ipport}:{local_port}"
        else:
            ip = get_public_ip()
            payload_str = f"{ip}:443"

        encrypted_payload = encrypt_payload(payload_str, encryption_key)
        client_info_json = json.dumps({"payload_b64": encrypted_payload})

        logging.info("Triggering V2 workflow via 'gh'...")
        trigger_command = [
            'gh', 'workflow', 'run', 'v2_workflow.yml',
            '--repo', repo,
            '--field', f'mode={mode}',
            '--field', f'client_info_json={client_info_json}',
            '--ref', 'main'
        ]
        _ = subprocess.run(trigger_command, check=True, capture_output=True)
        logging.info("Workflow triggered successfully.")

        logging.info("Waiting 5 seconds for the new run to appear...")
        time.sleep(5)
        try:
            logging.info("Attempting to find the run ID (single attempt)...")
            run_list_json_str = subprocess.run(
                ['gh', 'run', 'list', '--workflow=v2_workflow.yml', '--repo', repo, '--limit=1', '--json', 'databaseId'],
                capture_output=True, text=True, check=True
            ).stdout
            run_list = cast(list[dict[str, int]], json.loads(run_list_json_str))
            if run_list:
                run_id = run_list[0]['databaseId']
                logging.info(f"Detected new run with ID: {run_id}")
        except (IndexError, json.JSONDecodeError, subprocess.CalledProcessError) as e:
            logging.warning(f"Could not immediately find run ID, but workflow was triggered. Error: {e}")

        if not run_id:
            raise AppError("Could not find the triggered workflow run on the first attempt.")

        logging.info(f"Workflow run {run_id} is active on GitHub.")
        logging.info("You can download artifacts (e.g., wg_user.conf) manually from the GitHub UI when the run completes.")
        _ = input("Press ENTER to exit this script (the workflow will continue), or press Ctrl+C to cancel the workflow run.\n")
        logging.info("Exiting script. The workflow will continue to run on GitHub.")

    except (AppError, subprocess.CalledProcessError) as e:
        logging.error(f"An error occurred: {e}")
        # FIX: Check that both run_id and repo have been successfully assigned.
        if run_id and repo:
            logging.info(f"Attempting to cancel run {run_id}...")
            _ = subprocess.run(['gh', 'run', 'cancel', str(run_id), '--repo', repo])
        sys.exit(1)
    except KeyboardInterrupt:
        logging.info("\nCtrl+C detected.")
        # FIX: Check that both run_id and repo have been successfully assigned.
        if run_id and repo:
            logging.info(f"Attempting to cancel run {run_id}...")
            _ = subprocess.run(['gh', 'run', 'cancel', str(run_id), '--repo', repo])
        logging.info("Exiting gracefully.")
        sys.exit(0)

if __name__ == "__main__":
    main()
