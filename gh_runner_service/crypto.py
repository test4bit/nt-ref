# gh_runner_service/crypto.py
import subprocess
import tempfile

from .common.exceptions import AppError
from .common.utils import run_command

def decrypt_payload(encrypted_payload_hex: str, key: str) -> str:
    """
    Decrypts a hex-encoded payload using OpenSSL.
    This function first decodes the hex string back into the original Base64
    string, then uses a temporary file to pass it to OpenSSL for decryption.
    This method is robust against shell interpretation issues.
    """
    try:
        # Step 1: Decode the hex string back to the original Base64 string
        encrypted_payload_b64 = bytes.fromhex(encrypted_payload_hex).decode('utf-8')
    except (ValueError, TypeError) as e:
        raise AppError(f"Failed to decode hex payload: {e}")

    # Step 2: Prepare the OpenSSL command
    command = ["openssl", "enc", "-d", "-aes-256-cbc", "-a", "-pbkdf2", "-md", "sha256", "-pass", f"pass:{key}"]
    
    # Step 3: Use a temporary file to pass the Base64 data to OpenSSL
    try:
        with tempfile.NamedTemporaryFile(mode='w', delete=True, suffix=".txt", encoding='utf-8') as tmp:
            tmp.write(encrypted_payload_b64)
            tmp.flush()  # Ensure data is written to disk before openssl reads it
            
            command_with_file = command + ["-in", tmp.name]
            
            # Use a simple join here as the command is safe and contains no user input
            process = run_command(" ".join(command_with_file))
            return process.stdout.strip()
    except Exception as e:
        # Re-raise with a more informative message if something goes wrong
        raise AppError(f"OpenSSL decryption process failed: {e}")


def encrypt_payload(payload: str, key: str) -> str:
    """
    Encrypts a payload using OpenSSL and returns a git-safe, hex-encoded string.
    The process is: payload -> aes-256-cbc -> base64 -> hex.
    This ensures the final string has no special characters that could be
    mangled by git or shell environments.
    """
    command = ["openssl", "enc", "-aes-256-cbc", "-a", "-pbkdf2", "-salt", "-md", "sha256", "-pass", f"pass:{key}"]
    try:
        # Step 1: Encrypt the raw payload to Base64
        process = subprocess.run(
            command, 
            input=payload.encode('utf-8'),  # Ensure input is bytes
            capture_output=True, 
            check=True
        )
        base64_payload = process.stdout
        
        # Step 2: Convert the resulting Base64 bytes to a hex string for transport
        return base64_payload.hex()
    except subprocess.CalledProcessError as e:
        stderr_output = e.stderr.decode('utf-8').strip()
        raise AppError(f"Payload encryption failed: {stderr_output}")
