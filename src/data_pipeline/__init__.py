"""SecureCode AI - Data Pipeline Package

This package contains modules for fetching and processing vulnerability data
from various sources including CVE, GitHub Security Advisories, and OWASP.
"""

__version__ = "0.1.0"

from src.data_pipeline.cve_fetcher import CVEFetcher
from src.data_pipeline.github_scraper import GitHubSecurityScraper
from src.data_pipeline.preprocessor import CodePreprocessor

__all__ = [
    "CVEFetcher",
    "GitHubSecurityScraper", 
    "CodePreprocessor",
]