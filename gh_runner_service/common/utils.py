# gh_runner_service/common/utils.py
import logging
import os
import subprocess
from typing import cast # Need to import cast

from .exceptions import AppError

def run_command(command: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    """Helper to run a shell command and log its output."""
    logging.info(f"Executing: {command}")
    try:
        # Since text=True, the successful return's stdout/stderr are strings.
        return subprocess.run(command, shell=True, check=check, text=True, capture_output=True)
    except subprocess.CalledProcessError as e:
        logging.error(f"Command failed with exit code {e.returncode}")

        # FIX: Use `cast` to explicitly tell the linter the type of these attributes.
        # Because text=True was used, we expect `str` or `None`.
        stdout_val = cast(str | None, e.stdout)
        stderr_val = cast(str | None, e.stderr)

        # Now, work with the safely typed variables.
        stdout_log = stdout_val.strip() if stdout_val else "No stdout"
        stderr_log = stderr_val.strip() if stderr_val else "No stderr"

        logging.error(f"STDOUT: {stdout_log}")
        logging.error(f"STDERR: {stderr_log}")
        raise AppError(f"Execution failed for command: {command}") from e

def get_env_or_fail(var_name: str) -> str:
    """Gets an environment variable or raises a specific error if not found."""
    value = os.getenv(var_name)
    if not value:
        raise AppError(f"Required environment variable '{var_name}' is not set.")
    return value

def check_dependencies(*cmds: str) -> None:
    """Checks if required command-line tools are installed."""
    for cmd in cmds:
        if subprocess.run(['which', cmd], capture_output=True).returncode != 0:
            raise AppError(f"Required command '{cmd}' not found. Please install it and ensure it's in your PATH.")
