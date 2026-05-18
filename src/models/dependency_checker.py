"""Dependency Vulnerability Checker

Checks dependencies for known vulnerabilities.
"""

import logging
import re
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class DependencyVulnerability:
    """Dependency vulnerability."""
    package: str
    version: str
    vulnerability_id: str
    severity: str
    description: str
    fixed_version: Optional[str] = None


class DependencyChecker:
    """Checks project dependencies for vulnerabilities."""
    
    # Common known vulnerabilities (simplified example)
    KNOWN_VULNS = {
        "lodash": {"<4.17.21": {"id": "CVE-2021-23337", "severity": "high"}},
        "django": {"<3.2.9": {"id": "CVE-2021-44420", "severity": "high"}},
        "requests": {"<2.25.1": {"id": "CVE-2021-3236", "severity": "medium"}},
        "pyyaml": {"<5.4": {"id": "CVE-2020-14343", "severity": "high"}},
    }
    
    async def check_requirements(self, content: str) -> list[DependencyVulnerability]:
        """Check Python requirements.txt for vulnerabilities.
        
        Args:
            content: requirements.txt content
            
        Returns:
            List of vulnerable dependencies
        """
        findings = []
        
        # Parse requirements
        for line in content.split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            
            # Parse package==version
            match = re.match(r"^([a-zA-Z0-9\-_]+)([=!<>~]+)(.+?)(?:\s*#.*)?$", line)
            if not match:
                continue
            
            package, operator, version = match.groups()
            package_lower = package.lower()
            
            # Check against known vulnerabilities
            if package_lower in self.KNOWN_VULNS:
                for vuln_version, vuln_info in self.KNOWN_VULNS[package_lower].items():
                    if self._version_matches(version, vuln_version):
                        findings.append(DependencyVulnerability(
                            package=package,
                            version=version,
                            vulnerability_id=vuln_info["id"],
                            severity=vuln_info["severity"],
                            description=f"{package} {version} has known vulnerability {vuln_info['id']}"
                        ))
        
        return findings
    
    async def check_package_json(self, content: str) -> list[DependencyVulnerability]:
        """Check package.json for vulnerabilities.
        
        Args:
            content: package.json content
            
        Returns:
            List of vulnerable dependencies
        """
        import json
        findings = []
        
        try:
            data = json.loads(content)
            deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
            
            for package, version_spec in deps.items():
                package_lower = package.lower()
                
                # Extract version from semver spec
                version = re.sub(r"^[~^>=<]*", "", version_spec)
                
                if package_lower in self.KNOWN_VULNS:
                    for vuln_version, vuln_info in self.KNOWN_VULNS[package_lower].items():
                        if self._version_matches(version, vuln_version):
                            findings.append(DependencyVulnerability(
                                package=package,
                                version=version,
                                vulnerability_id=vuln_info["id"],
                                severity=vuln_info["severity"],
                                description=f"{package} {version} has known vulnerability {vuln_info['id']}"
                            ))
        except Exception as e:
            logger.warning(f"Error parsing package.json: {e}")
        
        return findings
    
    @staticmethod
    def _version_matches(version: str, vuln_spec: str) -> bool:
        """Check if version matches vulnerability spec.
        
        Args:
            version: Package version
            vuln_spec: Vulnerability version spec (e.g., "<4.17.21")
            
        Returns:
            True if version is vulnerable
        """
        from packaging import version as pkg_version
        
        try:
            v = pkg_version.parse(version)
            
            if vuln_spec.startswith("<"):
                return v < pkg_version.parse(vuln_spec[1:])
            elif vuln_spec.startswith("<="):
                return v <= pkg_version.parse(vuln_spec[2:])
            elif vuln_spec.startswith(">"):
                return v > pkg_version.parse(vuln_spec[1:])
            elif vuln_spec.startswith(">="):
                return v >= pkg_version.parse(vuln_spec[2:])
            elif vuln_spec.startswith("=="):
                return v == pkg_version.parse(vuln_spec[2:])
            
            return False
        except:
            return False
