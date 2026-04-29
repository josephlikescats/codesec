"""Tests for SecureCode AI Data Pipeline"""

import pytest
from src.data_pipeline.cve_fetcher import CVEFetcher, CVEEntry
from src.data_pipeline.github_scraper import GitHubSecurityScraper, GitHubAdvisory
from src.data_pipeline.preprocessor import CodePreprocessor, ProcessedCode


class TestCVEFetcher:
    """Tests for CVE Fetcher."""
    
    @pytest.mark.asyncio
    async def test_cve_fetcher_initialization(self):
        """Test CVE fetcher can be initialized."""
        fetcher = CVEFetcher()
        assert fetcher is not None
        assert fetcher.base_url == "https://services.nvd.nist.gov/rest/json"
    
    @pytest.mark.asyncio
    async def test_cve_entry_creation(self):
        """Test CVE entry dataclass."""
        from datetime import datetime
        entry = CVEEntry(
            cve_id="CVE-2023-1234",
            description="Test vulnerability",
            severity=7.5,
            published_date=datetime.now()
        )
        assert entry.cve_id == "CVE-2023-1234"
        assert entry.severity == 7.5


class TestGitHubSecurityScraper:
    """Tests for GitHub Security Scraper."""
    
    @pytest.mark.asyncio
    async def test_scraper_initialization(self):
        """Test scraper can be initialized."""
        scraper = GitHubSecurityScraper()
        assert scraper is not None
        assert scraper.BASE_URL == "https://api.github.com/advisories"
    
    @pytest.mark.asyncio
    async def test_advisory_creation(self):
        """Test advisory dataclass."""
        from datetime import datetime
        advisory = GitHubAdvisory(
            ghsa_id="GHSA-1234",
            cve_id="CVE-2023-1234",
            summary="Test advisory",
            description="Test description",
            severity="HIGH",
            published_date=datetime.now(),
            updated_date=datetime.now()
        )
        assert advisory.ghsa_id == "GHSA-1234"
        assert advisory.severity == "HIGH"


class TestCodePreprocessor:
    """Tests for Code Preprocessor."""
    
    def test_preprocessor_initialization(self):
        """Test preprocessor can be initialized."""
        preprocessor = CodePreprocessor()
        assert preprocessor is not None
        assert preprocessor.max_length == 512
    
    def test_preprocess_vulnerable_code(self):
        """Test preprocessing detects vulnerable code."""
        preprocessor = CodePreprocessor()
        code = '''
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return db.execute(query)
'''
        result = preprocessor.preprocess(code, "python")
        assert result.has_vulnerability is True
        assert result.vulnerability_type == "sql_injection"
    
    def test_preprocess_safe_code(self):
        """Test preprocessing detects safe code."""
        preprocessor = CodePreprocessor()
        code = '''
def get_user(user_id):
    return db.query("SELECT * FROM users WHERE id = %s", (user_id,))
'''
        result = preprocessor.preprocess(code, "python")
        assert result.has_vulnerability is False
    
    def test_detect_command_injection(self):
        """Test command injection detection."""
        preprocessor = CodePreprocessor()
        code = '''
import os
os.system(user_input)
'''
        result = preprocessor.preprocess(code, "python")
        assert result.has_vulnerability is True
        assert result.vulnerability_type == "command_injection"
    
    def test_detect_hardcoded_secrets(self):
        """Test hardcoded secret detection."""
        preprocessor = CodePreprocessor()
        code = '''
API_KEY = "sk-1234567890abcdef"
'''
        result = preprocessor.preprocess(code, "python")
        assert result.has_vulnerability is True
        assert result.vulnerability_type == "hardcoded_secret"
    
    def test_extract_functions(self):
        """Test function extraction."""
        preprocessor = CodePreprocessor()
        code = '''
def function_one():
    pass

def function_two():
    pass
'''
        functions = preprocessor.extract_functions(code, "python")
        assert len(functions) >= 2
    
    def test_language_detection(self):
        """Test language detection from extension."""
        preprocessor = CodePreprocessor()
        assert preprocessor._detect_language(".py") == "python"
        assert preprocessor._detect_language(".js") == "javascript"
        assert preprocessor._detect_language(".ts") == "typescript"
        assert preprocessor._detect_language(".go") == "go"
        assert preprocessor._detect_language(".rs") == "rust"