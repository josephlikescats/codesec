"""Tests for SecureCode AI API"""

import pytest
from fastapi.testclient import TestClient
from src.api.main import app


class TestAPI:
    """Tests for API endpoints."""
    
    @pytest.fixture
    def client(self):
        """Create test client."""
        return TestClient(app)
    
    def test_root_endpoint(self, client):
        """Test root endpoint."""
        response = client.get("/")
        assert response.status_code == 200
        assert "message" in response.json()
    
    def test_health_check(self, client):
        """Test health check endpoint."""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "version" in data
    
    def test_scan_endpoint(self, client):
        """Test scan endpoint."""
        response = client.post("/api/v1/scan", json={
            "code": "def get_user(user_id):\n    query = f'SELECT * FROM users WHERE id = {user_id}'\n    return db.execute(query)",
            "language": "python"
        })
        assert response.status_code == 200
        data = response.json()
        assert "scan_id" in data
        assert "findings" in data
        assert "has_issues" in data
    
    def test_scan_with_command_injection(self, client):
        """Test scan with command injection."""
        response = client.post("/api/v1/scan", json={
            "code": "import os\nos.system(user_input)",
            "language": "python"
        })
        assert response.status_code == 200
        data = response.json()
        assert data["has_issues"] is True
    
    def test_scan_with_hardcoded_secret(self, client):
        """Test scan with hardcoded secret."""
        response = client.post("/api/v1/scan", json={
            "code": 'API_KEY = "sk-1234567890abcdef"',
            "language": "python"
        })
        assert response.status_code == 200
        data = response.json()
        assert data["has_issues"] is True
    
    def test_scan_safe_code(self, client):
        """Test scan with safe code."""
        response = client.post("/api/v1/scan", json={
            "code": "def get_user(user_id):\n    return db.query('SELECT * FROM users WHERE id = %s', (user_id,))",
            "language": "python"
        })
        assert response.status_code == 200
    
    def test_batch_scan(self, client):
        """Test batch scan endpoint."""
        response = client.post("/api/v1/scan/batch", json={
            "files": [
                {"code": "import os\nos.system(user_input)", "language": "python", "file_path": "test1.py"},
                {"code": "def test():\n    pass", "language": "python", "file_path": "test2.py"}
            ]
        })
        assert response.status_code == 200
        data = response.json()
        assert "results" in data
        assert data["total_files"] == 2
    
    def test_test_generation(self, client):
        """Test test generation endpoint."""
        response = client.post("/api/v1/tests/generate", json={
            "findings": [
                {
                    "id": "test_1",
                    "category": "injection",
                    "severity": "high",
                    "title": "SQL Injection",
                    "description": "SQL injection vulnerability",
                    "code_snippet": "query = f'SELECT * FROM users WHERE id = {user_id}'",
                    "line_number": 1,
                    "cwe_id": "CWE-89"
                }
            ],
            "language": "python"
        })
        assert response.status_code == 200
        data = response.json()
        assert "tests" in data
        assert data["count"] > 0
    
    def test_remediation_suggestion(self, client):
        """Test remediation suggestion endpoint."""
        response = client.post("/api/v1/fix/suggest", json={
            "findings": [
                {
                    "id": "test_1",
                    "category": "injection",
                    "severity": "high",
                    "title": "SQL Injection",
                    "description": "SQL injection vulnerability",
                    "code_snippet": "query = f'SELECT * FROM users WHERE id = {user_id}'",
                    "line_number": 1,
                    "cwe_id": "CWE-89"
                }
            ]
        })
        assert response.status_code == 200
        data = response.json()
        assert "suggestions" in data
        assert data["count"] > 0
    
    def test_stats_endpoint(self, client):
        """Test stats endpoint."""
        response = client.get("/api/v1/stats")
        assert response.status_code == 200
        data = response.json()
        assert "total_scans" in data
        assert "vulnerabilities_found" in data
    
    def test_get_scan_by_id(self, client):
        """Test get scan by ID."""
        response = client.get("/api/v1/scan/test-123")
        assert response.status_code == 200
    
    def test_get_test_by_id(self, client):
        """Test get test by ID."""
        response = client.get("/api/v1/tests/test-123")
        assert response.status_code == 200
    
    def test_apply_fix(self, client):
        """Test apply fix endpoint."""
        response = client.post("/api/v1/fix/apply", json={"fix_id": "fix-123"})
        assert response.status_code == 200
    
    def test_fix_history(self, client):
        """Test fix history endpoint."""
        response = client.get("/api/v1/fix/history")
        assert response.status_code == 200