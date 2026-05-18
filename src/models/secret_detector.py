"""Secret Detection Module

Detects secrets, API keys, and hardcoded credentials in code.
"""

import logging
import re
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class SecretFinding:
    """Detected secret."""
    type: str  # password, api_key, private_key, etc.
    line_number: int
    severity: str  # critical, high
    message: str
    evidence: str


class SecretDetector:
    """Detects hardcoded secrets and credentials."""
    
    PATTERNS = {
        "aws_key": re.compile(r"AKIA[0-9A-Z]{16}", re.IGNORECASE),
        "private_key": re.compile(r"-----BEGIN RSA PRIVATE KEY-----", re.IGNORECASE),
        "github_token": re.compile(r"ghp_[A-Za-z0-9_]{36,255}", re.IGNORECASE),
        "slack_token": re.compile(r"xox[baprs]-[0-9]{12}-[0-9]{12}-[A-Za-z0-9_-]{32,34}", re.IGNORECASE),
        "api_key": re.compile(r"api[_-]?key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{20,})['\"]?", re.IGNORECASE),
        "password": re.compile(r"password['\"]?\s*[:=]\s*['\"]?([^'\";\n]{8,})['\"]?", re.IGNORECASE),
        "jwt": re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", re.IGNORECASE),
    }
    
    async def detect_secrets(self, code: str, filepath: str = "unknown") -> list[SecretFinding]:
        """Detect secrets in code.
        
        Args:
            code: Code content
            filepath: File path for reference
            
        Returns:
            List of detected secrets
        """
        findings = []
        lines = code.split("\n")
        
        for line_num, line in enumerate(lines, 1):
            # Skip comments
            if line.strip().startswith("#"):
                continue
            
            for secret_type, pattern in self.PATTERNS.items():
                matches = pattern.finditer(line)
                for match in matches:
                    findings.append(SecretFinding(
                        type=secret_type,
                        line_number=line_num,
                        severity="critical",
                        message=f"Potential {secret_type.replace('_', ' ')} detected",
                        evidence=match.group()[:50]  # Truncate for safety
                    ))
        
        return findings
