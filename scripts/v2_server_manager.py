#!/usr/bin/env python3
import json
import logging
import os
import sys
from pathlib import Path
from typing import cast

# We can reuse all our existing modules!
from modules.common import AppError, get_env_or_fail
from modules.config import ClientInfo
from modules.crypto import decrypt_payload
from modules.server_setup import base, wireguard, xray

# --- Setup ---
LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)

SCRIPT_DIR = Path(__file__).resolve().parent
BASE_DIR = SCRIPT_DIR.parent
CONFIG_DIR = BASE_DIR / "config"

def main() -> None:
    """Main entry point for the V2 server manager script."""
    try:
        logging.info("--- V2 Workflow Started ---")

        # Step 1: Get config from environment variables and workflow inputs
        encryption_key = get_env_or_fail("GHA_PAYLOAD_KEY")
        wg_private_key = os.getenv("WG_PRIVATE_KEY")
        xray_uuid = os.getenv("XRAY_UUID")
        
        mode = get_env_or_fail("INPUT_MODE")
        client_info_json = get_env_or_fail("INPUT_CLIENT_INFO_JSON")
        
        logging.info(f"Mode received: {mode}")

        # Step 2: Decrypt payload
        encrypted_payload = json.loads(client_info_json)["payload"]
        decrypted_payload = decrypt_payload(encrypted_payload, encryption_key)
        
        parts = decrypted_payload.split(":")
        client_info = ClientInfo(
            ip=parts[0],
            port=int(parts[1]),
            local_port=int(parts[2]) if len(parts) > 2 else None
        )
        logging.info("Payload decrypted successfully.")

        # Step 3: Validate secrets for the chosen mode
        if mode in ["direct-connect", "hole-punch"] and not wg_private_key:
            raise AppError("WG_PRIVATE_KEY secret is required for this mode.")
        if mode in ["xray", "xray-direct"] and not xray_uuid:
            raise AppError("XRAY_UUID secret is required for this mode.")

        # Step 4: Run setup
        logging.info(f"--- Setting up mode '{mode}' ---")
        base.setup_common_environment(BASE_DIR)

        artifact_created = False
        if mode == "direct-connect":
            wireguard.setup_wireguard_client(client_info, wg_private_key, BASE_DIR, CONFIG_DIR)
        elif mode == "hole-punch":
            # The setup function now needs to return a boolean if it creates an artifact
            artifact_created = wireguard.setup_wireguard_server(client_info, wg_private_key, BASE_DIR, CONFIG_DIR)
        elif mode == "xray":
            xray.setup_xray(client_info, cast(str, xray_uuid), BASE_DIR, CONFIG_DIR)
        elif mode == "xray-direct":
            xray.setup_xray_direct(client_info, cast(str, xray_uuid), BASE_DIR, CONFIG_DIR)

        # Step 5: Set an output for the workflow to know if an artifact was made
        # This is how we communicate back to the YAML file.
        if artifact_created:
            print("::set-output name=artifact_created::true")

        logging.info("--- V2 Workflow Finished Successfully ---")

    except AppError as e:
        logging.error(f"A critical error occurred: {e}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
