"""
Custom exceptions for the security scanner engine.
"""


class ScannerEngineError(Exception):
    """Base exception for all scanner-engine errors."""


class InvalidTargetError(ScannerEngineError):
    """Raised when a target fails validation (e.g. not localhost)."""


class ScannerNotFoundError(ScannerEngineError):
    """Raised when the ScannerManager is asked to run an unregistered scanner."""


class ScannerExecutionError(ScannerEngineError):
    """
    Raised internally when a scanner fails during execution.

    This is caught by the ScannerManager and converted into a ScannerError
    record rather than being allowed to abort the whole scan.
    """

    def __init__(self, scanner_name: str, original_exception: Exception):
        self.scanner_name = scanner_name
        self.original_exception = original_exception
        super().__init__(f"Scanner '{scanner_name}' failed: {original_exception}")


class DiscoveryError(ScannerEngineError):
    """Raised when API discovery fails in an unrecoverable way."""


class HttpClientError(ScannerEngineError):
    """Raised for unexpected HTTP client failures."""
