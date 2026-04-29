"""SecureCode AI - API Package

This package contains the FastAPI server and endpoints for vulnerability
scanning, test generation, and remediation.
"""

__version__ = "0.1.0"

from src.api.main import app

__all__ = ["app"]