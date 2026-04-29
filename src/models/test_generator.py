"""Security Test Generator Module

Generates unit tests for detected vulnerabilities.
"""

import logging
import json
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
class GeneratedTest:
    """Represents a generated security test."""
    id: str
    name: str
    description: str
    test_code: str
    vulnerability_id: str
    language: str
    created_at: datetime = field(default_factory=datetime.now)
    passes: Optional[bool] = None
    error_message: Optional[str] = None


class SecurityTestGenerator:
    """Generates security tests for detected vulnerabilities."""
    
    # Test templates for different vulnerability types
    TEST_TEMPLATES = {
        VulnerabilityCategory.INJECTION: {
            "python": '''import unittest
from unittest.mock import patch, MagicMock
import sys

class {class_name}(unittest.TestCase):
    """Security test for {vuln_type} vulnerability."""
    
    def setUp(self):
        self.target = {target_module}.{target_class}()
    
    def test_{test_name}_should_reject_malicious_input(self):
        """Test that malicious {vuln_type} input is rejected."""
        malicious_inputs = [
            {malicious_inputs}
        ]
        
        for malicious_input in malicious_inputs:
            with self.assertRaises({expected_exception}):
                self.target.{target_method}(malicious_input)
    
    def test_{test_name}_should_accept_valid_input(self):
        """Test that valid input is accepted."""
        valid_inputs = [
            {valid_inputs}
        ]
        
        for valid_input in valid_inputs:
            result = self.target.{target_method}(valid_input)
            self.assertIsNotNone(result)


if __name__ == "__main__":
    unittest.main()
''',
            "javascript": '''const assert = require("assert");

describe("{class_name}", function() {{
    describe("{test_name}", function() {{
        it("should reject malicious input", function() {{
            const maliciousInputs = {malicious_inputs};
            for (const input of maliciousInputs) {{
                assert.throws(() => {{
                    target.{target_method}(input);
                }}, /{expected_exception}/);
            }}
        }});
        
        it("should accept valid input", function() {{
            const validInputs = {valid_inputs};
            for (const input of validInputs) {{
                const result = target.{target_method}(input);
                assert(result !== null, "Should return a result");
            }}
        }});
    }});
}});
'''
        },
        VulnerabilityCategory.XSS: {
            "python": '''import unittest
import html

class {class_name}(unittest.TestCase):
    """Security test for XSS vulnerability."""
    
    def test_{test_name}_should_sanitize_html(self):
        """Test that HTML is properly sanitized."""
        malicious_inputs = [
            "<script>alert('xss')</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
        ]
        
        for input in malicious_inputs:
            sanitized = html.escape(input)
            self.assertNotIn("<script>", sanitized)
            self.assertNotIn("javascript:", sanitized.lower())
    
    def test_{test_name}_should_allow_safe_html(self):
        """Test that safe HTML is allowed."""
        safe_inputs = [
            "<b>bold</b>",
            "<i>italic</i>",
            "<p>paragraph</p>",
        ]
        
        for input in safe_inputs:
            # Safe HTML should be preserved after sanitization
            sanitized = html.escape(input)
            self.assertIn(input, sanitized)
''',
            "javascript": '''const assert = require("assert");

describe("{class_name}", function() {{
    describe("XSS sanitization", function() {{
        it("should sanitize malicious HTML", function() {{
            const maliciousInputs = [
                "<script>alert('xss')</script>",
                "<img src=x onerror=alert(1)>",
                "javascript:alert(1)"
            ];
            
            for (const input of maliciousInputs) {{
                const sanitized = sanitize(input);
                assert(!sanitized.includes("<script>"), "Should remove script tags");
                assert(!sanitized.toLowerCase().includes("javascript:"), "Should remove javascript:");
            }}
        }});
    }});
}});
'''
        },
        VulnerabilityCategory.SENSITIVE_DATA: {
            "python": '''import unittest
import os
import json

class {class_name}(unittest.TestCase):
    """Security test for hardcoded secrets."""
    
    def test_{test_name}_should_not_hardcode_secrets(self):
        """Test that secrets are not hardcoded."""
        # Scan source files for hardcoded secrets
        secret_patterns = [
            r"password\s*=\s*['\"](?!None|false)",
            r"api[_-]?key\s*=\s*['\"]",
            r"secret\s*=\s*['\"]",
            r"token\s*=\s*['\"][a-zA-Z0-9_-]{20,}",
        ]
        
        import re
        source_files = ["src/module.py"]  # Add source files to scan
        
        for file_path in source_files:
            try:
                with open(file_path, "r") as f:
                    content = f.read()
                    
                for pattern in secret_patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    self.assertEqual(
                        len(matches), 0,
                        f"Found hardcoded secret in {{file_path}}: {{matches}}"
                    )
            except FileNotFoundError:
                pass
    
    def test_{test_name}_should_use_environment_variables(self):
        """Test that environment variables are used for secrets."""
        required_env_vars = ["API_KEY", "SECRET_KEY", "DATABASE_PASSWORD"]
        
        for var in required_env_vars:
            value = os.environ.get(var)
            self.assertIsNotNone(
                value,
                f"Environment variable {{var}} should be set"
            )
            self.assertGreater(
                len(value), 0,
                f"Environment variable {{var}} should not be empty"
            )
''',
            "javascript": '''const assert = require("assert");
const dotenv = require("dotenv");

describe("{class_name}", function() {{
    describe("Secret management", function() {{
        it("should not hardcode secrets in source", function() {{
            const fs = require("fs");
            const sourceFiles = ["src/module.js"];
            
            for (const file of sourceFiles) {{
                try {{
                    const content = fs.readFileSync(file, "utf8");
                    const secretPatterns = [
                        /password\s*=\s*["'][^"']+["']/i,
                        /api[_-]?key\s*=\s*["'][^"']+["']/i,
                        /secret\s*=\s*["'][^"']+["']/i
                    ];
                    
                    for (const pattern of secretPatterns) {{
                        const matches = content.match(pattern);
                        assert(!matches, `Found hardcoded secret in ${{file}}`);
                    }}
                }} catch (e) {{
                    // File may not exist
                }}
            }}
        }});
    }});
}});
'''
        },
        VulnerabilityCategory.DESERIALIZATION: {
            "python": '''import unittest
import yaml

class {class_name}(unittest.TestCase):
    """Security test for insecure deserialization."""
    
    def test_{test_name}_should_use_safe_loader(self):
        """Test that yaml.safe_load is used instead of yaml.load."""
        import ast
        import inspect
        
        source_files = ["src/module.py"]  # Add source files to scan
        
        for file_path in source_files:
            try:
                with open(file_path, "r") as f:
                    tree = ast.parse(f.read())
                
                # Check for unsafe yaml.load calls
                for node in ast.walk(tree):
                    if isinstance(node, ast.Call):
                        if isinstance(node.func, ast.Attribute):
                            if (node.func.attr == "load" and 
                                hasattr(node.func.value, "id") and 
                                node.func.value.id == "yaml"):
                                # Check if SafeLoader is used
                                if not any(
                                    arg.id == "SafeLoader" 
                                    for arg in node.args 
                                    if isinstance(arg, ast.Name)
                                ):
                                    self.fail(
                                        f"Found unsafe yaml.load in {file_path}. "
                                        "Use yaml.safe_load or yaml.load(data, Loader=yaml.SafeLoader)"
                                    )
            except FileNotFoundError:
                pass
    
    def test_{test_name}_should_reject_untrusted_yaml(self):
        """Test that untrusted YAML is properly validated."""
        malicious_yaml = """
!!python/object/apply:os.system
args: ['echo hacked']
"""
        
        with self.assertRaises(yaml.YAMLError):
            yaml.unsafe_load(malicious_yaml)
''',
            "javascript": '''const assert = require("assert");

describe("{class_name}", function() {{
    describe("Deserialization security", function() {{
        it("should use safe JSON parsing", function() {{
            const maliciousInput = '{{"__proto__": {{"evil": true}}}}';
            
            try {{
                const parsed = JSON.parse(maliciousInput);
                // Should not execute arbitrary code
                assert(parsed !== null);
            }} catch (e) {{
                // Good - rejected invalid input
            }}
        }});
    }});
}});
'''
        },
    }
    
    def __init__(self):
        self.templates = self.TEST_TEMPLATES
    
    async def generate_tests(
        self,
        findings: list[VulnerabilityFinding],
        language: str = "python"
    ) -> list[GeneratedTest]:
        """Generate security tests for detected vulnerabilities."""
        tests = []
        
        for finding in findings:
            test = await self._generate_test(finding, language)
            if test:
                tests.append(test)
        
        return tests
    
    async def _generate_test(
        self,
        finding: VulnerabilityFinding,
        language: str
    ) -> Optional[GeneratedTest]:
        """Generate a test for a single vulnerability."""
        template = self._get_template(finding.category, language)
        
        if not template:
            logger.warning(f"No template for category {finding.category}")
            return None
        
        # Generate test code from template
        test_code = self._fill_template(template, finding, language)
        
        return GeneratedTest(
            id=f"test_{finding.id}",
            name=f"test_{finding.category.value}_{finding.line_number}",
            description=f"Security test for {finding.title}",
            test_code=test_code,
            vulnerability_id=finding.id,
            language=language
        )
    
    def _get_template(
        self,
        category: VulnerabilityCategory,
        language: str
    ) -> Optional[str]:
        """Get test template for vulnerability category."""
        category_templates = self.templates.get(category, {})
        return category_templates.get(language)
    
    def _fill_template(
        self,
        template: str,
        finding: VulnerabilityFinding,
        language: str
    ) -> str:
        """Fill template with vulnerability details."""
        malicious_inputs = self._format_input_list(
            self._get_malicious_inputs(finding.category), language
        )
        valid_inputs = self._format_input_list(
            self._get_valid_inputs(finding.category), language
        )

        replacements = {
            "{class_name}": f"Test{finding.category.value.title().replace('_', '')}",
            "{test_name}": f"{finding.category.value}_{finding.line_number}",
            "{vuln_type}": finding.category.value,
            "{target_module}": "module",
            "{target_class}": "Class",
            "{target_method}": "method",
            "{malicious_inputs}": malicious_inputs,
            "{valid_inputs}": valid_inputs,
            "{expected_exception}": self._get_expected_exception(finding.category),
        }
        
        result = template
        for placeholder, value in replacements.items():
            result = result.replace(placeholder, value)
        
        return result

    def _format_input_list(self, values: list[str], language: str) -> str:
        """Format a list of inputs as code literals for templates."""
        if not values:
            return ""

        if language == "javascript":
            return json.dumps(values)

        # Python templates expect one item per line inside list brackets.
        return ",\n            ".join(repr(value) for value in values)
    
    def _get_malicious_inputs(self, category: VulnerabilityCategory) -> list[str]:
        """Get malicious inputs for testing."""
        inputs_map = {
            VulnerabilityCategory.INJECTION: [
                "'; DROP TABLE users; --",
                "' OR '1'='1",
                "1; DELETE FROM users",
            ],
            VulnerabilityCategory.XSS: [
                "<script>alert('xss')</script>",
                "<img src=x onerror=alert(1)>",
                "javascript:alert(1)",
            ],
            VulnerabilityCategory.SENSITIVE_DATA: [
                "sk-1234567890abcdef",
                "password123",
            ],
            VulnerabilityCategory.DESERIALIZATION: [
                '!!python/object/apply:os.system ["echo hacked"]',
            ],
        }
        return inputs_map.get(category, [])
    
    def _get_valid_inputs(self, category: VulnerabilityCategory) -> list[str]:
        """Get valid inputs for testing."""
        inputs_map = {
            VulnerabilityCategory.INJECTION: [
                "user123",
                "123",
            ],
            VulnerabilityCategory.XSS: [
                "<b>bold</b>",
                "plain text",
            ],
            VulnerabilityCategory.SENSITIVE_DATA: [
                "os.environ.get('API_KEY')",
            ],
            VulnerabilityCategory.DESERIALIZATION: [
                '{"key": "value"}',
            ],
        }
        return inputs_map.get(category, [])
    
    def _get_expected_exception(self, category: VulnerabilityCategory) -> str:
        """Get expected exception for vulnerability category."""
        exceptions_map = {
            VulnerabilityCategory.INJECTION: "SQLInjectionError",
            VulnerabilityCategory.XSS: "XSSError",
            VulnerabilityCategory.SENSITIVE_DATA: "SecretFoundError",
            VulnerabilityCategory.DESERIALIZATION: "DeserializationError",
        }
        return exceptions_map.get(category, "SecurityError")
    
    async def validate_test(
        self,
        test: GeneratedTest
    ) -> tuple[bool, Optional[str]]:
        """Validate that a generated test is syntactically correct."""
        try:
            # Try to parse the test code
            import ast
            ast.parse(test.test_code)
            return True, None
        except SyntaxError as e:
            return False, str(e)


# Example usage
async def main():
    from src.models.vulnerability_detector import VulnerabilityDetector
    
    # First detect vulnerabilities
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
    
    # Then generate tests
    generator = SecurityTestGenerator()
    tests = await generator.generate_tests(findings, "python")
    
    print(f"Generated {len(tests)} security tests:")
    for test in tests:
        print(f"\n{test.name}")
        print(test.test_code[:500] + "...")


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())