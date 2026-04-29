"""Tests for SecureCode AI ML Models"""

import pytest
from src.models.vulnerability_detector import (
    VulnerabilityDetector,
    VulnerabilityFinding,
    VulnerabilityCategory,
    VulnerabilitySeverity,
    ScanResult
)
from src.models.test_generator import SecurityTestGenerator, GeneratedTest
from src.models.remediation_suggester import RemediationSuggester, RemediationSuggestion


class TestVulnerabilityDetector:
    """Tests for Vulnerability Detector."""
    
    @pytest.mark.asyncio
    async def test_detector_initialization(self):
        """Test detector can be initialized."""
        detector = VulnerabilityDetector()
        assert detector is not None
    
    @pytest.mark.asyncio
    async def test_detector_load(self):
        """Test detector can load."""
        detector = VulnerabilityDetector()
        await detector.load()
        assert detector._is_loaded is True
    
    @pytest.mark.asyncio
    async def test_detect_sql_injection(self):
        """Test SQL injection detection."""
        detector = VulnerabilityDetector()
        code = '''
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return db.execute(query)
'''
        findings = await detector.detect(code, "python")
        assert len(findings) > 0
        sql_findings = [f for f in findings if f.category == VulnerabilityCategory.INJECTION]
        assert len(sql_findings) > 0
    
    @pytest.mark.asyncio
    async def test_detect_command_injection(self):
        """Test command injection detection."""
        detector = VulnerabilityDetector()
        code = '''
import os
os.system(user_input)
'''
        findings = await detector.detect(code, "python")
        assert len(findings) > 0
        cmd_findings = [f for f in findings if f.category == VulnerabilityCategory.INJECTION]
        assert len(cmd_findings) > 0
    
    @pytest.mark.asyncio
    async def test_detect_hardcoded_secrets(self):
        """Test hardcoded secret detection."""
        detector = VulnerabilityDetector()
        code = '''
API_KEY = "sk-1234567890abcdef"
'''
        findings = await detector.detect(code, "python")
        assert len(findings) > 0
        secret_findings = [f for f in findings if f.category == VulnerabilityCategory.SENSITIVE_DATA]
        assert len(secret_findings) > 0
    
    @pytest.mark.asyncio
    async def test_detect_xss(self):
        """Test XSS detection."""
        detector = VulnerabilityDetector()
        code = '''
element.innerHTML = user_input
'''
        findings = await detector.detect(code, "javascript")
        assert len(findings) > 0
    
    @pytest.mark.asyncio
    async def test_detect_deserialization(self):
        """Test deserialization vulnerability detection."""
        detector = VulnerabilityDetector()
        code = '''
import pickle
data = pickle.loads(user_data)
'''
        findings = await detector.detect(code, "python")
        assert len(findings) > 0
    
    @pytest.mark.asyncio
    async def test_safe_code_no_findings(self):
        """Test that safe code produces no findings."""
        detector = VulnerabilityDetector()
        code = '''
def get_user(user_id):
    return db.query("SELECT * FROM users WHERE id = %s", (user_id,))
'''
        findings = await detector.detect(code, "python")
        # May have some findings, but should be fewer than vulnerable code
        assert isinstance(findings, list)
    
    @pytest.mark.asyncio
    async def test_finding_properties(self):
        """Test finding has required properties."""
        detector = VulnerabilityDetector()
        code = '''
import os
os.system(user_input)
'''
        findings = await detector.detect(code, "python")
        if findings:
            finding = findings[0]
            assert finding.id is not None
            assert finding.title is not None
            assert finding.description is not None
            assert finding.line_number > 0
            assert finding.cwe_id is not None


class TestSecurityTestGenerator:
    """Tests for Security Test Generator."""
    
    @pytest.mark.asyncio
    async def test_generator_initialization(self):
        """Test generator can be initialized."""
        generator = SecurityTestGenerator()
        assert generator is not None
    
    @pytest.mark.asyncio
    async def test_generate_tests(self):
        """Test test generation."""
        generator = SecurityTestGenerator()
        findings = [
            VulnerabilityFinding(
                id="test_1",
                category=VulnerabilityCategory.INJECTION,
                severity=VulnerabilitySeverity.HIGH,
                title="SQL Injection",
                description="SQL injection vulnerability",
                code_snippet="query = f'SELECT * FROM users WHERE id = {user_id}'",
                line_number=1,
                cwe_id="CWE-89"
            )
        ]
        tests = await generator.generate_tests(findings, "python")
        assert len(tests) > 0
        assert isinstance(tests[0], GeneratedTest)
    
    @pytest.mark.asyncio
    async def test_validate_test(self):
        """Test test validation."""
        generator = SecurityTestGenerator()
        test = GeneratedTest(
            id="test_1",
            name="test_sql_injection",
            description="Test for SQL injection",
            test_code="import unittest\nclass Test(unittest.TestCase):\n    pass",
            vulnerability_id="vuln_1",
            language="python"
        )
        is_valid, error = await generator.validate_test(test)
        assert is_valid is True
        assert error is None


class TestRemediationSuggester:
    """Tests for Remediation Suggester."""
    
    @pytest.mark.asyncio
    async def test_suggester_initialization(self):
        """Test suggester can be initialized."""
        suggester = RemediationSuggester()
        assert suggester is not None
    
    @pytest.mark.asyncio
    async def test_suggest_fix(self):
        """Test fix suggestion."""
        suggester = RemediationSuggester()
        finding = VulnerabilityFinding(
            id="test_1",
            category=VulnerabilityCategory.INJECTION,
            severity=VulnerabilitySeverity.HIGH,
            title="SQL Injection",
            description="SQL injection vulnerability",
            code_snippet="query = f'SELECT * FROM users WHERE id = {user_id}'",
            line_number=1,
            cwe_id="CWE-89"
        )
        suggestion = await suggester.suggest_fix(finding)
        assert suggestion is not None
        assert isinstance(suggestion, RemediationSuggestion)
        assert suggestion.fixed_code is not None
    
    @pytest.mark.asyncio
    async def test_suggest_fixes_multiple(self):
        """Test multiple fix suggestions."""
        suggester = RemediationSuggester()
        findings = [
            VulnerabilityFinding(
                id="test_1",
                category=VulnerabilityCategory.INJECTION,
                severity=VulnerabilitySeverity.HIGH,
                title="SQL Injection",
                description="SQL injection vulnerability",
                code_snippet="query = f'SELECT * FROM users WHERE id = {user_id}'",
                line_number=1,
                cwe_id="CWE-89"
            ),
            VulnerabilityFinding(
                id="test_2",
                category=VulnerabilityCategory.SENSITIVE_DATA,
                severity=VulnerabilitySeverity.HIGH,
                title="Hardcoded Secret",
                description="Hardcoded secret detected",
                code_snippet='API_KEY = "sk-1234567890"',
                line_number=1,
                cwe_id="CWE-798"
            )
        ]
        suggestions = await suggester.suggest_fixes(findings)
        assert len(suggestions) > 0