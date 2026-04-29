"""Remediation Suggester Module

Suggests code fixes for detected vulnerabilities.
"""

import logging
from typing import Any, Optional
from dataclasses import dataclass, field
from datetime import datetime

from src.models.vulnerability_detector import (
    VulnerabilityFinding, 
    VulnerabilityCategory,
    VulnerabilitySeverity
)

logger = logging.getLogger(__name__)


@dataclass
class RemediationSuggestion:
    """Represents a code fix suggestion."""
    id: str
    vulnerability_id: str
    title: str
    description: str
    original_code: str
    fixed_code: str
    explanation: str
    references: list[str] = field(default_factory=list)
    confidence: float = 0.0
    created_at: datetime = field(default_factory=datetime.now)


class RemediationSuggester:
    """Suggests remediation code for vulnerabilities."""
    
    # Remediation templates for different vulnerability types
    REMEDIATION_TEMPLATES = {
        VulnerabilityCategory.INJECTION: {
            "python": {
                "sql_injection": {
                    "title": "Use Parameterized Queries",
                    "description": "Replace string formatting with parameterized queries to prevent SQL injection.",
                    "original_pattern": r'f"SELECT.*?\{.*?\}"',
                    "fixed_template": '''# Use parameterized queries
cursor.execute(
    "SELECT * FROM users WHERE id = %s",
    (user_id,)
)
result = cursor.fetchone()''',
                    "explanation": "Parameterized queries separate SQL logic from data, preventing injection attacks.",
                    "references": [
                        "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                        "https://docs.python.org/3/library/sqlite3.html"
                    ]
                },
                "command_injection": {
                    "title": "Avoid Shell Commands with User Input",
                    "description": "Use subprocess with shell=False or avoid shell commands entirely.",
                    "original_pattern": r'os\.system\(',
                    "fixed_template": '''# Use subprocess.run with shell=False
import subprocess

result = subprocess.run(
    ["ls", "-la", user_input],  # Pass as list, not string
    capture_output=True,
    text=True,
    shell=False
)''',
                    "explanation": "Using shell=False prevents command injection through shell metacharacters.",
                    "references": [
                        "https://docs.python.org/3/library/subprocess.html"
                    ]
                },
            }
        },
        VulnerabilityCategory.XSS: {
            "python": {
                "xss": {
                    "title": "Escape HTML Content",
                    "description": "Escape user input before rendering to prevent XSS attacks.",
                    "original_pattern": r'innerHTML\s*=',
                    "fixed_template": '''import html

# Escape user input before rendering
safe_content = html.escape(user_input)
element.innerText = safe_content  # Use innerText instead of innerHTML
# Or use a sanitization library:
# from bleach import clean
# safe_content = clean(user_input, tags=[], attributes={}, styles=[], strip=True)''',
                    "explanation": "Using innerText instead of innerHTML automatically escapes HTML entities.",
                    "references": [
                        "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
                    ]
                }
            }
        },
        VulnerabilityCategory.SENSITIVE_DATA: {
            "python": {
                "hardcoded_secret": {
                    "title": "Use Environment Variables for Secrets",
                    "description": "Store secrets in environment variables instead of hardcoding them.",
                    "original_pattern": r'(password|api[_-]?key|secret|token)\s*=\s*["\'][^"\']+["\']',
                    "fixed_template": '''import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Get secrets from environment
API_KEY = os.environ.get("API_KEY")
DATABASE_PASSWORD = os.environ.get("DATABASE_PASSWORD")

# For required secrets, raise error if not set
if not API_KEY:
    raise ValueError("API_KEY environment variable is not set")''',
                    "explanation": "Environment variables keep secrets out of source code and allow different configurations per environment.",
                    "references": [
                        "https://12factor.net/config"
                    ]
                }
            }
        },
        VulnerabilityCategory.DESERIALIZATION: {
            "python": {
                "insecure_deserialization": {
                    "title": "Use Safe Deserializers",
                    "description": "Use safe loaders that don't execute arbitrary code.",
                    "original_pattern": r'yaml\.load\(',
                    "fixed_template": '''import yaml

# Use SafeLoader instead of default loader
data = yaml.safe_load(user_input)

# Or explicitly specify SafeLoader
data = yaml.load(user_input, Loader=yaml.SafeLoader)''',
                    "explanation": "SafeLoader prevents arbitrary code execution during YAML parsing.",
                    "references": [
                        "https://pyyaml.org/wiki/PyYAMLDocumentation"
                    ]
                },
                "pickle_injection": {
                    "title": "Use JSON Instead of Pickle",
                    "description": "Replace pickle with JSON for untrusted data.",
                    "original_pattern": r'pickle\.load\(',
                    "fixed_template": '''import json
import pickle  # Only for trusted data

# For untrusted data, use JSON
data = json.loads(user_input)

# If you must use pickle, use a signed serializer
# import hmac, pickle
# data = pickle.loads(user_input, fix_imports=True)''',
                    "explanation": "JSON cannot execute arbitrary code, making it safe for untrusted data.",
                    "references": [
                        "https://docs.python.org/3/library/pickle.html"
                    ]
                }
            }
        },
        VulnerabilityCategory.BROKEN_ACCESS: {
            "python": {
                "path_traversal": {
                    "title": "Validate and Sanitize File Paths",
                    "description": "Validate that file paths stay within allowed directories.",
                    "original_pattern": r'open\s*\(\s*.*?\+',
                    "fixed_template": '''import os
from pathlib import Path

def get_safe_file_path(user_input, base_dir):
    """Validate and resolve file path to prevent path traversal."""
    base_path = Path(base_dir).resolve()
    requested_path = (base_path / user_input).resolve()
    
    # Ensure the resolved path is within the base directory
    if not requested_path.is_relative_to(base_path):
        raise ValueError("Invalid file path")
    
    return requested_path

# Usage
file_path = get_safe_file_path(user_input, "/app/uploads")''',
                    "explanation": "Using Path.resolve() and checking is_relative_to prevents directory traversal attacks.",
                    "references": [
                        "https://owasp.org/www-community/attacks/Path_Traversal"
                    ]
                }
            }
        },
    }
    
    def __init__(self):
        self.templates = self.REMEDIATION_TEMPLATES
    
    async def suggest_fix(
        self,
        finding: VulnerabilityFinding
    ) -> Optional[RemediationSuggestion]:
        """Suggest a fix for a detected vulnerability."""
        # Get category-specific remediation
        category_templates = self.templates.get(finding.category, {})
        
        if not category_templates:
            return self._get_generic_remediation(finding)
        
        # Try to find a specific remediation for the vulnerability type
        vuln_type = finding.category.value
        if vuln_type in category_templates:
            template = category_templates[vuln_type]
            return self._create_suggestion(finding, template)
        
        # Fall back to generic remediation
        return self._get_generic_remediation(finding)
    
    async def suggest_fixes(
        self,
        findings: list[VulnerabilityFinding]
    ) -> list[RemediationSuggestion]:
        """Suggest fixes for multiple vulnerabilities."""
        suggestions = []
        
        for finding in findings:
            suggestion = await self.suggest_fix(finding)
            if suggestion:
                suggestions.append(suggestion)
        
        return suggestions
    
    def _create_suggestion(
        self,
        finding: VulnerabilityFinding,
        template: dict
    ) -> RemediationSuggestion:
        """Create a remediation suggestion from a template."""
        return RemediationSuggestion(
            id=f"fix_{finding.id}",
            vulnerability_id=finding.id,
            title=template["title"],
            description=template["description"],
            original_code=finding.code_snippet,
            fixed_code=template["fixed_template"],
            explanation=template["explanation"],
            references=template.get("references", []),
            confidence=0.9
        )
    
    def _get_generic_remediation(
        self,
        finding: VulnerabilityFinding
    ) -> RemediationSuggestion:
        """Get generic remediation for a vulnerability."""
        return RemediationSuggestion(
            id=f"fix_{finding.id}",
            vulnerability_id=finding.id,
            title=f"Fix {finding.title}",
            description=finding.description,
            original_code=finding.code_snippet,
            fixed_code="# Review and fix this code according to security best practices",
            explanation=f"Review the code at line {finding.line_number} and apply security best practices.",
            references=finding.references,
            confidence=0.5
        )
    
    def get_remediation_for_category(
        self,
        category: VulnerabilityCategory
    ) -> dict:
        """Get all remediation templates for a category."""
        return self.templates.get(category, {})


# Example usage
async def main():
    from src.models.vulnerability_detector import VulnerabilityDetector
    
    # Detect vulnerabilities
    detector = VulnerabilityDetector()
    test_code = '''
import os
import subprocess
import pickle

def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return db.execute(query)

def run_command(cmd):
    os.system(cmd)

API_KEY = "sk-1234567890abcdef"
'''
    
    findings = await detector.detect(test_code, "python")
    
    # Generate remediation suggestions
    suggester = RemediationSuggester()
    suggestions = await suggester.suggest_fixes(findings)
    
    print(f"Generated {len(suggestions)} remediation suggestions:")
    for suggestion in suggestions:
        print(f"\n{'='*60}")
        print(f"Title: {suggestion.title}")
        print(f"Description: {suggestion.description}")
        print(f"\nOriginal Code:")
        print(suggestion.original_code)
        print(f"\nFixed Code:")
        print(suggestion.fixed_code)
        print(f"\nExplanation: {suggestion.explanation}")


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())