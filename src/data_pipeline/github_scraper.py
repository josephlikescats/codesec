"""GitHub Security Advisory Scraper

Fetches security advisories and vulnerability reports from GitHub.
"""

import asyncio
import logging
from datetime import datetime
from typing import Any, Optional
from dataclasses import dataclass, field

import httpx

logger = logging.getLogger(__name__)


@dataclass
class GitHubAdvisory:
    """Represents a GitHub Security Advisory."""
    ghsa_id: str
    cve_id: Optional[str]
    summary: str
    description: str
    severity: str
    published_date: datetime
    updated_date: datetime
    vulnerabilities: list[dict] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    patches: list[str] = field(default_factory=list)
    cwe_ids: list[str] = field(default_factory=list)
    ecosystem: Optional[str] = None
    package_name: Optional[str] = None


class GitHubSecurityScraper:
    """Scrapes security advisories from GitHub Advisory Database."""
    
    BASE_URL = "https://api.github.com/advisories"
    
    def __init__(self, token: Optional[str] = None):
        self.token = token
        self.client = httpx.AsyncClient(
            timeout=30.0,
            headers={
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                **(({"Authorization": f"Bearer {token}"} if token else {}))
            }
        )
    
    async def fetch_advisory(self, ghsa_id: str) -> Optional[GitHubAdvisory]:
        """Fetch a specific advisory by GHSA ID."""
        url = f"{self.BASE_URL}/{ghsa_id}"
        
        try:
            response = await self.client.get(url)
            response.raise_for_status()
            data = response.json()
            
            return self._parse_advisory(data)
        except httpx.HTTPError as e:
            logger.error(f"Failed to fetch advisory {ghsa_id}: {e}")
            return None
    
    async def fetch_advisories(
        self,
        ecosystem: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100
    ) -> list[GitHubAdvisory]:
        """Fetch security advisories with optional filters."""
        params = {"per_page": min(limit, 100)}
        
        if ecosystem:
            params["ecosystem"] = ecosystem
        if severity:
            params["severity"] = severity
        
        advisories = []
        page = 1
        
        while len(advisories) < limit:
            params["page"] = page
            params["per_page"] = min(100, limit - len(advisories))
            
            try:
                response = await self.client.get(self.BASE_URL, params=params)
                response.raise_for_status()
                data = response.json()
                
                if not data:
                    break
                    
                for item in data:
                    advisory = self._parse_advisory(item)
                    if advisory:
                        advisories.append(advisory)
                
                if len(data) < 100:
                    break
                page += 1
                
            except httpx.HTTPError as e:
                logger.error(f"Failed to fetch advisories: {e}")
                break
        
        return advisories[:limit]
    
    async def fetch_by_cve(self, cve_id: str) -> Optional[GitHubAdvisory]:
        """Fetch advisory by CVE ID."""
        url = self.BASE_URL
        params = {"cve_id": cve_id}
        
        try:
            response = await self.client.get(url, params=params)
            response.raise_for_status()
            data = response.json()
            
            if data:
                return self._parse_advisory(data[0])
        except httpx.HTTPError as e:
            logger.error(f"Failed to fetch advisory for CVE {cve_id}: {e}")
        
        return None
    
    async def search_advisories(self, query: str, limit: int = 50) -> list[GitHubAdvisory]:
        """Search advisories by keyword."""
        # GitHub API doesn't have full-text search for advisories
        # So we fetch all and filter locally
        all_advisories = await self.fetch_advisories(limit=100)
        
        query_lower = query.lower()
        filtered = [
            adv for adv in all_advisories
            if query_lower in adv.summary.lower() or query_lower in adv.description.lower()
        ]
        
        return filtered[:limit]
    
    def _parse_advisory(self, data: dict) -> Optional[GitHubAdvisory]:
        """Parse advisory data from GitHub API."""
        try:
            ghsa_id = data.get("ghsa_id", "")
            cve_id = data.get("cve_id")
            summary = data.get("summary", "")
            description = data.get("description", "")
            severity = data.get("severity", "UNKNOWN")
            
            # Parse dates
            published = data.get("published_at", "")
            updated = data.get("updated_at", "")
            
            published_date = datetime.fromisoformat(published.replace("Z", "+00:00")) if published else datetime.now()
            updated_date = datetime.fromisoformat(updated.replace("Z", "+00:00")) if updated else datetime.now()
            
            # Extract vulnerabilities
            vulnerabilities = data.get("vulnerabilities", [])
            
            # Extract references
            references = [ref.get("url", "") for ref in data.get("references", [])]
            
            # Extract patches
            patches = []
            for ref in data.get("identifiers", []):
                if ref.get("type") == "PATCH":
                    patches.append(ref.get("value", ""))
            
            # Extract CWEs
            cwe_ids = []
            for identifier in data.get("identifiers", []):
                if identifier.get("type") == "CWE":
                    cwe_ids.append(identifier.get("value", ""))
            
            # Extract ecosystem and package
            ecosystem = None
            package_name = None
            if vulnerabilities:
                first_vuln = vulnerabilities[0]
                ecosystem = first_vuln.get("package", {}).get("ecosystem")
                package_name = first_vuln.get("package", {}).get("name")
            
            return GitHubAdvisory(
                ghsa_id=ghsa_id,
                cve_id=cve_id,
                summary=summary,
                description=description,
                severity=severity,
                published_date=published_date,
                updated_date=updated_date,
                vulnerabilities=vulnerabilities,
                references=references,
                patches=patches,
                cwe_ids=cwe_ids,
                ecosystem=ecosystem,
                package_name=package_name
            )
            
        except Exception as e:
            logger.warning(f"Failed to parse advisory: {e}")
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
    async with GitHubSecurityScraper() as scraper:
        # Fetch recent advisories
        advisories = await scraper.fetch_advisories(ecosystem="pip", limit=10)
        print(f"Found {len(advisories)} Python advisories")
        
        for adv in advisories[:3]:
            print(f"\n{adv.ghsa_id} ({adv.severity})")
            print(f"Summary: {adv.summary[:100]}...")


if __name__ == "__main__":
    asyncio.run(main())