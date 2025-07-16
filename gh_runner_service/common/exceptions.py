# gh_runner_service/common/exceptions.py

class AppError(Exception):
    """Base custom exception for the application for graceful error handling."""
    pass


class ConfigurationError(AppError):
    """
    Raised for errors related to configuration, such as missing files,
    invalid settings, or missing environment variables.
    """
    pass


class NetworkError(AppError):
    """
    Raised for errors related to network operations, such as API requests,
    STUN client failures, or other connection issues.
    """
    pass


class CryptographyError(AppError):
    """
    Raised for errors during encryption or decryption, such as an
    invalid key or corrupted payload.
    """
    pass


class ProcessExecutionError(AppError):
    """
    Raised when a required external command (like 'wg', 'iptables', 'xray')
    fails to execute correctly.
    """
    pass
