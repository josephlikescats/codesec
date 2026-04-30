"""FastAPI Main Application

SecureCode AI API server for vulnerability scanning, test generation,
and remediation suggestions.
"""

import logging
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, HTTPException, BackgroundTasks, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from dotenv import load_dotenv

from src.models.vulnerability_detector import (
    VulnerabilityDetector, 
    VulnerabilityFinding,
    ScanResult,
    VulnerabilityCategory,
    VulnerabilitySeverity
)
from src.models.test_generator import SecurityTestGenerator, GeneratedTest
from src.models.remediation_suggester import RemediationSuggester, RemediationSuggestion

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


# Initialize models
detector = VulnerabilityDetector()
test_generator = SecurityTestGenerator()
remediation_suggester = RemediationSuggester()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    logger.info("Starting SecureCode AI API...")
    await detector.load()
    logger.info("Models loaded successfully")
    yield
    logger.info("Shutting down SecureCode AI API...")


# Create FastAPI app
app = FastAPI(
    title="SecureCode AI",
    description="AI-Driven DevSecOps Platform for automated security testing",
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ================== Request Models ==================

class ScanRequest(BaseModel):
    """Request model for code scanning."""
    code: str = Field(..., description="Code to scan for vulnerabilities")
    language: str = Field(default="python", description="Programming language")
    file_path: Optional[str] = Field(None, description="Optional file path")


class BatchScanRequest(BaseModel):
    """Request model for batch scanning."""
    files: list[dict] = Field(..., description="List of files to scan")


class TestGenerationRequest(BaseModel):
    """Request model for test generation."""
    findings: list[dict] = Field(..., description="Vulnerability findings")
    language: str = Field(default="python", description="Programming language")


class RemediationRequest(BaseModel):
    """Request model for remediation suggestions."""
    findings: list[dict] = Field(..., description="Vulnerability findings")


class ApplyFixRequest(BaseModel):
    """Request model for applying a remediation fix."""
    fix_id: str = Field(..., description="Suggested fix ID to apply")


# ================== Response Models ==================

class ScanResponse(BaseModel):
    """Response model for scan results."""
    scan_id: str
    file_path: Optional[str]
    language: str
    findings: list[dict]
    scan_time_ms: float
    lines_scanned: int
    has_issues: bool


class TestGenerationResponse(BaseModel):
    """Response model for test generation."""
    tests: list[dict]
    count: int


class RemediationResponse(BaseModel):
    """Response model for remediation suggestions."""
    suggestions: list[dict]
    count: int


class HealthResponse(BaseModel):
    """Response model for health check."""
    status: str
    version: str
    timestamp: datetime


# ================== API Endpoints ==================

@app.get("/", tags=["Root"])
async def root():
    """Root endpoint."""
    return {
        "message": "Welcome to SecureCode AI",
        "docs": "/docs",
        "redoc": "/redoc"
    }


@app.get("/health", tags=["Health"], response_model=HealthResponse)
async def health_check():
    """Health check endpoint."""
    return HealthResponse(
        status="healthy",
        version="0.1.0",
        timestamp=datetime.now()
    )


@app.post("/api/v1/scan", tags=["Scanner"], response_model=ScanResponse)
async def scan_code(
    request: ScanRequest,
    background_tasks: BackgroundTasks
):
    """Scan code for vulnerabilities.
    
    This endpoint analyzes code for security vulnerabilities using
    pattern-based detection and ML-based analysis.
    """
    import time
    start_time = time.time()
    
    try:
        # Detect vulnerabilities
        findings = await detector.detect(
            code=request.code,
            language=request.language,
            file_path=request.file_path
        )
        
        # Convert findings to dict
        findings_dict = [
            {
                "id": f.id,
                "category": f.category.value,
                "severity": f.severity.value,
                "title": f.title,
                "description": f.description,
                "code_snippet": f.code_snippet,
                "line_number": f.line_number,
                "cwe_id": f.cwe_id,
                "confidence": f.confidence,
                "remediation": f.remediation,
                "references": f.references
            }
            for f in findings
        ]
        
        scan_time_ms = (time.time() - start_time) * 1000
        lines_scanned = len(request.code.splitlines())
        
        return ScanResponse(
            scan_id=str(uuid.uuid4()),
            file_path=request.file_path,
            language=request.language,
            findings=findings_dict,
            scan_time_ms=scan_time_ms,
            lines_scanned=lines_scanned,
            has_issues=len(findings) > 0
        )
        
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/scan/batch", tags=["Scanner"], response_model=dict)
async def batch_scan(request: BatchScanRequest):
    """Scan multiple files for vulnerabilities.
    
    This endpoint scans multiple code files in a single request.
    """
    results = []
    
    for file_data in request.files:
        try:
            code = file_data.get("code", "")
            language = file_data.get("language", "python")
            file_path = file_data.get("file_path")
            
            findings = await detector.detect(
                code=code,
                language=language,
                file_path=file_path
            )
            
            results.append({
                "file_path": file_path,
                "language": language,
                "findings": [
                    {
                        "id": f.id,
                        "category": f.category.value,
                        "severity": f.severity.value,
                        "title": f.title,
                        "line_number": f.line_number,
                        "cwe_id": f.cwe_id
                    }
                    for f in findings
                ],
                "has_issues": len(findings) > 0
            })
            
        except Exception as e:
            logger.error(f"Failed to scan file {file_data.get('file_path')}: {e}")
            results.append({
                "file_path": file_data.get("file_path"),
                "error": str(e)
            })
    
    return {
        "results": results,
        "total_files": len(request.files),
        "files_with_issues": sum(1 for r in results if r.get("has_issues", False))
    }


@app.get("/api/v1/scan/{scan_id}", tags=["Scanner"])
async def get_scan(scan_id: str):
    """Get scan results by ID.
    
    This endpoint retrieves previously stored scan results.
    """
    # In production, this would fetch from database
    return {
        "scan_id": scan_id,
        "status": "completed",
        "message": "Scan results would be retrieved from database"
    }


@app.post("/api/v1/tests/generate", tags=["Test Generation"], response_model=TestGenerationResponse)
async def generate_tests(request: TestGenerationRequest):
    """Generate security tests for detected vulnerabilities.
    
    This endpoint generates unit tests targeting detected security vulnerabilities.
    """
    try:
        # Convert dict findings back to VulnerabilityFinding objects
        findings = []
        for f in request.findings:
            finding = VulnerabilityFinding(
                id=f.get("id", ""),
                category=VulnerabilityCategory(f.get("category", "injection")),
                severity=VulnerabilitySeverity(f.get("severity", "medium")),
                title=f.get("title", ""),
                description=f.get("description", ""),
                code_snippet=f.get("code_snippet", ""),
                line_number=f.get("line_number", 0),
                cwe_id=f.get("cwe_id"),
                confidence=f.get("confidence", 0.0)
            )
            findings.append(finding)
        
        # Generate tests
        tests = await test_generator.generate_tests(findings, request.language)
        
        # Convert to dict
        tests_dict = [
            {
                "id": t.id,
                "name": t.name,
                "description": t.description,
                "test_code": t.test_code,
                "vulnerability_id": t.vulnerability_id,
                "language": t.language
            }
            for t in tests
        ]
        
        return TestGenerationResponse(
            tests=tests_dict,
            count=len(tests_dict)
        )
        
    except Exception as e:
        logger.error(f"Test generation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/tests/{test_id}", tags=["Test Generation"])
async def get_test(test_id: str):
    """Get generated test by ID.
    
    This endpoint retrieves a previously generated test.
    """
    return {
        "test_id": test_id,
        "status": "completed",
        "message": "Test would be retrieved from database"
    }


@app.post("/api/v1/fix/suggest", tags=["Remediation"], response_model=RemediationResponse)
async def suggest_fixes(request: RemediationRequest):
    """Suggest remediation code for detected vulnerabilities.
    
    This endpoint provides code fixes for detected security issues.
    """
    try:
        # Convert dict findings back to VulnerabilityFinding objects
        findings = []
        for f in request.findings:
            finding = VulnerabilityFinding(
                id=f.get("id", ""),
                category=VulnerabilityCategory(f.get("category", "injection")),
                severity=VulnerabilitySeverity(f.get("severity", "medium")),
                title=f.get("title", ""),
                description=f.get("description", ""),
                code_snippet=f.get("code_snippet", ""),
                line_number=f.get("line_number", 0),
                cwe_id=f.get("cwe_id"),
                confidence=f.get("confidence", 0.0)
            )
            findings.append(finding)
        
        # Generate remediation suggestions
        suggestions = await remediation_suggester.suggest_fixes(findings)
        
        # Convert to dict
        suggestions_dict = [
            {
                "id": s.id,
                "vulnerability_id": s.vulnerability_id,
                "title": s.title,
                "description": s.description,
                "original_code": s.original_code,
                "fixed_code": s.fixed_code,
                "explanation": s.explanation,
                "references": s.references,
                "confidence": s.confidence
            }
            for s in suggestions
        ]
        
        return RemediationResponse(
            suggestions=suggestions_dict,
            count=len(suggestions_dict)
        )
        
    except Exception as e:
        logger.error(f"Remediation suggestion failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/fix/apply", tags=["Remediation"])
async def apply_fix(request: ApplyFixRequest):
    """Apply a suggested fix.
    
    This endpoint applies a remediation fix to the codebase.
    """
    return {
        "fix_id": request.fix_id,
        "status": "applied",
        "message": "Fix would be applied to the codebase"
    }


@app.get("/api/v1/fix/history", tags=["Remediation"])
async def get_fix_history():
    """Get fix history.
    
    This endpoint retrieves the history of applied fixes.
    """
    return {
        "fixes": [],
        "message": "Fix history would be retrieved from database"
    }


# ================== File Upload Endpoints ==================

@app.post("/api/v1/scan/file", tags=["Scanner"])
async def scan_file(
    file: UploadFile = File(...),
    language: str = "python"
):
    """Scan a file for vulnerabilities.
    
    This endpoint accepts file uploads for vulnerability scanning.
    """
    try:
        # Read file content
        content = await file.read()
        code = content.decode("utf-8")
        
        # Scan the code
        findings = await detector.detect(
            code=code,
            language=language,
            file_path=file.filename
        )
        
        return {
            "scan_id": str(uuid.uuid4()),
            "file_name": file.filename,
            "language": language,
            "findings": [
                {
                    "id": f.id,
                    "category": f.category.value,
                    "severity": f.severity.value,
                    "title": f.title,
                    "description": f.description,
                    "code_snippet": f.code_snippet,
                    "line_number": f.line_number,
                    "cwe_id": f.cwe_id,
                    "confidence": f.confidence
                }
                for f in findings
            ],
            "has_issues": len(findings) > 0,
            "scan_time_ms": 0,
            "lines_scanned": len(code.splitlines())
        }
        
    except Exception as e:
        logger.error(f"File scan failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/scan/project", tags=["Scanner"])
async def scan_project(
    files: list[UploadFile] = File(...),
    language: str = "python"
):
    """Scan an entire project for vulnerabilities.
    
    This endpoint accepts multiple file uploads for comprehensive project scanning.
    """
    import time
    start_time = time.time()
    
    results = []
    total_findings = 0
    total_lines = 0
    
    for file in files:
        try:
            # Skip non-code files
            if file.filename.endswith(('.md', '.txt', '.json', '.yaml', '.yml', '.toml', '.gitignore')):
                continue
                
            # Read file content
            content = await file.read()
            code = content.decode("utf-8", errors="ignore")
            
            # Detect language from extension
            file_lang = language
            if file.filename.endswith('.py'):
                file_lang = 'python'
            elif file.filename.endswith(('.js', '.jsx')):
                file_lang = 'javascript'
            elif file.filename.endswith(('.ts', '.tsx')):
                file_lang = 'typescript'
            elif file.filename.endswith('.java'):
                file_lang = 'java'
            elif file.filename.endswith('.go'):
                file_lang = 'go'
            elif file.filename.endswith('.rs'):
                file_lang = 'rust'
            
            # Scan the code
            findings = await detector.detect(
                code=code,
                language=file_lang,
                file_path=file.filename
            )
            
            findings_dict = [
                {
                    "id": f.id,
                    "category": f.category.value,
                    "severity": f.severity.value,
                    "title": f.title,
                    "description": f.description,
                    "code_snippet": f.code_snippet,
                    "line_number": f.line_number,
                    "cwe_id": f.cwe_id,
                    "confidence": f.confidence
                }
                for f in findings
            ]
            
            results.append({
                "file_name": file.filename,
                "language": file_lang,
                "findings": findings_dict,
                "has_issues": len(findings) > 0,
                "lines_scanned": len(code.splitlines())
            })
            
            total_findings += len(findings)
            total_lines += len(code.splitlines())
            
        except Exception as e:
            logger.error(f"Failed to scan file {file.filename}: {e}")
            results.append({
                "file_name": file.filename,
                "error": str(e)
            })
    
    scan_time_ms = (time.time() - start_time) * 1000
    
    # Aggregate findings by severity
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for r in results:
        for f in r.get("findings", []):
            sev = f.get("severity", "low")
            if sev in severity_counts:
                severity_counts[sev] += 1
    
    return {
        "scan_id": str(uuid.uuid4()),
        "project_name": "uploaded_project",
        "total_files": len(results),
        "files_with_issues": sum(1 for r in results if r.get("has_issues", False)),
        "total_findings": total_findings,
        "total_lines_scanned": total_lines,
        "scan_time_ms": scan_time_ms,
        "by_severity": severity_counts,
        "results": results
    }


# ================== Statistics Endpoints ==================

@app.get("/api/v1/stats", tags=["Statistics"])
async def get_stats():
    """Get platform statistics.
    
    This endpoint provides overall platform statistics.
    """
    return {
        "total_scans": 0,
        "vulnerabilities_found": 0,
        "tests_generated": 0,
        "fixes_applied": 0,
        "by_severity": {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0
        },
        "by_category": {
            "injection": 0,
            "xss": 0,
            "broken_auth": 0,
            "sensitive_data": 0
        }
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)