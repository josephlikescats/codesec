"""CVE Data Fetcher Module

Fetches vulnerability data from the National Vulnerability Database (NVD).
"""

import asyncio
import logging
from datetime import datetime
from typing import Any, Optional
from dataclasses import dataclass, field

import httpx
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)


@dataclass
class CVEEntry:
    """Represents a CVE vulnerability entry."""
    cve_id: str
    description: str
    severity: float
    published_date: datetime
    affected_products: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    vulnerable_code: Optional[str] = None
    fix_code: Optional[str] = None
    cwe_id: Optional[str] = None
    cvss_vector: Optional[str] = None


class CVEFetcher:
    """Fetches CVE data from NVD API."""
    
    def __init__(self, api_key: Optional[str] = None, base_url: str = "https://services.nvd.nist.gov/rest/json"):
        self.api_key = api_key
        self.base_url = base_url
        self.client = httpx.AsyncClient(
            timeout=30.0,
            headers={
                "Accept": "application/json",
                **(({"Api-Key": api_key} if api_key else {}))
            }
        )
    
    async def fetch_cve(self, cve_id: str) -> Optional[CVEEntry]:
        """Fetch a specific CVE by ID."""
        url = f"{self.base_url}/cves/2.0"
        params = {"cveId": cve_id}
        
        try:
            response = await self.client.get(url, params=params)
            response.raise_for_status()
            data = response.json()
            
            return self._parse_cve_response(data)
        except httpx.HTTPError as e:
            logger.error(f"Failed to fetch CVE {cve_id}: {e}")
            return None
    
    async def fetch_recent_cves(self, start_index: int = 0, results_per_page: int = 100) -> list[CVEEntry]:
        """Fetch recent CVE entries."""
        url = f"{self.base_url}/cves/2.0"
        params = {
            "startIndex": start_index,
            "resultsPerPage": results_per_page,
            "pubStartDate": "2023-01-01T00:00:00.000Z"
        }
        
        cves = []
        try:
            response = await self.client.get(url, params=params)
            response.raise_for_status()
            data = response.json()
            
            vulnerabilities = data.get("vulnerabilities", [])
            for vuln in vulnerabilities:
                cve = self._parse_cve_item(vuln)
                if cve:
                    cves.append(cve)
                    
        except httpx.HTTPError as e:
            logger.error(f"Failed to fetch recent CVEs: {e}")
        
        return cves
    
    async def fetch_by_keyword(self, keyword: str, limit: int = 50) -> list[CVEEntry]:
        """Search CVEs by keyword."""
        url = f"{self.base_url}/cves/2.0"
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": limit
        }
        
        cves = []
        try:
            response = await self.client.get(url, params=params)
            response.raise_for_status()
            data = response.json()
            
            vulnerabilities = data.get("vulnerabilities", [])
            for vuln in vulnerabilities:
                cve = self._parse_cve_item(vuln)
                if cve:
                    cves.append(cve)
                    
        except httpx.HTTPError as e:
            logger.error(f"Failed to search CVEs for '{keyword}': {e}")
        
        return cves
    
    def _parse_cve_item(self, vuln_data: dict) -> Optional[CVEEntry]:
        """Parse a CVE item from the API response."""
        try:
            cve_data = vuln_data.get("cve", {})
            cve_id = cve_data.get("id", "")
            
            # Extract description
            descriptions = cve_data.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break
            
            # Extract severity
            metrics = cve_data.get("metrics", {})
            cvss_data = metrics.get("cvssMetricV31", [{}])[0] if metrics.get("cvssMetricV31") else {}
            base_severity = cvss_data.get("cvssData", {}).get("baseSeverity", "UNKNOWN")
            base_score = cvss_data.get("cvssData", {}).get("baseScore", 0.0)
            
            # Extract published date
            published = cve_data.get("published", "")
            published_date = datetime.fromisoformat(published.replace("Z", "+00:00")) if published else datetime.now()
            
            # Extract references
            references = [ref.get("url", "") for ref in cve_data.get("references", [])]
            
            # Extract CWE
            cwe_id = None
            for problem_type in cve_data.get("problemTypes", []):
                for desc in problem_type.get("description", []):
                    if desc.get("type") == "CWE":
                        cwe_id = desc.get("value", "")
                        break
            
            return CVEEntry(
                cve_id=cve_id,
                description=description,
                severity=base_score,
                published_date=published_date,
                references=references,
                cwe_id=cwe_id
            )
            
        except Exception as e:
            logger.warning(f"Failed to parse CVE item: {e}")
            return None
    
    def _parse_cve_response(self, data: dict) -> Optional[CVEEntry]:
        """Parse CVE response from API."""
        vulnerabilities = data.get("vulnerabilities", [])
        if vulnerabilities:
            return self._parse_cve_item(vulnerabilities[0])
        return None
    
    async def close(self):
        """Close the HTTP client."""
        await self.client.aclose()
    
    async def __aenter__(self):
        return self
    
    async def __exit__(self, exc_type, exc_val, exc_tb):
        await self.close()


# Example usage
async def main():
    async with CVEFetcher() as fetcher:
        # Fetch a specific CVE
        cve = await fetcher.fetch_cve("CVE-2023-1234")
        if cve:
            print(f"CVE: {cve.cve_id}")
            print(f"Description: {cve.description}")
            print(f"Severity: {cve.severity}")
        
        # Search for SQL injection CVEs
        sql_cves = await fetcher.fetch_by_keyword("sql injection", limit=10)
        print(f"\nFound {len(sql_cves)} SQL injection CVEs")


if __name__ == "__main__":
    asyncio.run(main())