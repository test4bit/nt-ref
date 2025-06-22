# gh_runner_service/common/utils.py
import logging
import os
import subprocess

from .exceptions import AppError

def run_command(command: str, check: bool = True) -> subprocess.CompletedProcess:
    """Helper to run a shell command and log its output."""
    logging.info(f"Executing: {command}")
    try:
        # Using shell=True is necessary for commands with pipes, redirects, or backgrounding (&)
        return subprocess.run(command, shell=True, check=check, text=True, capture_output=True)
    except subprocess.CalledProcessError as e:
        logging.error(f"Command failed with exit code {e.returncode}")
        logging.error(f"STDOUT: {e.stdout.strip()}")
        logging.error(f"STDERR: {e.stderr.strip()}")
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
