"""SecureCode AI - CI/CD Integrations Package

This package contains integration modules for various CI/CD platforms.
"""

from .github_repo_scanner import GitHubRepositoryScanner

__version__ = "0.1.0"

__all__ = ["GitHubRepositoryScanner"]