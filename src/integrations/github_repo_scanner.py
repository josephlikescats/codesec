"""GitHub Repository Scanner

Handles cloning, analyzing, and scanning GitHub repositories.
"""

import asyncio
import logging
import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from subprocess import run, PIPE

try:
    import httpx
except Exception:
    httpx = None

logger = logging.getLogger(__name__)


@dataclass
class RepositoryInfo:
    """Information about a repository."""
    owner: str
    repo: str
    url: str
    language: str
    files_count: int
    total_lines: int
    primary_languages: dict[str, int]
    sensitive_files: list[str]
    error: Optional[str] = None


class GitHubRepositoryScanner:
    """Scans GitHub repositories for vulnerabilities."""
    
    CLONE_TIMEOUT = 300  # 5 minutes
    TEMP_DIR = Path(tempfile.gettempdir()) / "securecode_scans"
    SENSITIVE_PATTERNS = [
        "*.env*",
        "*secret*",
        "*password*",
        "*api_key*",
        "*token*",
        "*credential*",
        "*.pem",
        "*.key",
        "Dockerfile*",
        "docker-compose*",
        "*.yaml",
        "*.yml",
        "*config*",
    ]
    
    def __init__(self, token: Optional[str] = None):
        """Initialize the GitHub scanner.
        
        Args:
            token: GitHub personal access token for API calls
        """
        self.token = token
        if httpx is not None:
            self.client = httpx.AsyncClient(
                timeout=30.0,
                headers={
                    "Accept": "application/vnd.github+json",
                    **({"Authorization": f"Bearer {token}"} if token else {})
                }
            )
        else:
            self.client = None
        self.TEMP_DIR.mkdir(parents=True, exist_ok=True)
    
    async def clone_repository(self, owner: str, repo: str) -> Optional[Path]:
        """Clone a GitHub repository.
        
        Args:
            owner: Repository owner
            repo: Repository name
            
        Returns:
            Path to cloned repository or None if failed
        """
        clone_url = f"https://github.com/{owner}/{repo}.git"
        repo_path = self.TEMP_DIR / f"{owner}_{repo}"
        
        # Remove existing directory
        if repo_path.exists():
            shutil.rmtree(repo_path)
        
        try:
            logger.info(f"Cloning {clone_url}")
            result = run(
                ["git", "clone", "--depth", "1", clone_url, str(repo_path)],
                capture_output=True,
                timeout=self.CLONE_TIMEOUT,
                text=True
            )
            
            if result.returncode != 0:
                logger.error(f"Failed to clone {clone_url}: {result.stderr}")
                return None
            
            logger.info(f"Successfully cloned {clone_url}")
            return repo_path
            
        except Exception as e:
            logger.error(f"Error cloning {clone_url}: {e}")
            return None
    
    async def analyze_repository(self, repo_path: Path) -> Optional[RepositoryInfo]:
        """Analyze a cloned repository.
        
        Args:
            repo_path: Path to cloned repository
            
        Returns:
            RepositoryInfo with analysis results
        """
        try:
            owner, repo = repo_path.name.split("_", 1)
            
            # Count files and lines
            files_count = 0
            total_lines = 0
            primary_languages = {}
            sensitive_files = []
            
            language_extensions = {
                ".py": "Python",
                ".js": "JavaScript",
                ".ts": "TypeScript",
                ".java": "Java",
                ".go": "Go",
                ".rs": "Rust",
                ".cpp": "C++",
                ".c": "C",
                ".jsx": "JSX",
                ".tsx": "TSX",
            }
            
            for file_path in repo_path.rglob("*"):
                if file_path.is_file():
                    # Skip hidden files and common non-code directories
                    if any(part.startswith(".") for part in file_path.parts):
                        continue
                    if any(part in ["node_modules", "__pycache__", "venv", ".venv"] for part in file_path.parts):
                        continue
                    
                    files_count += 1
                    
                    # Count lines
                    try:
                        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                            total_lines += len(f.readlines())
                    except:
                        pass
                    
                    # Detect language
                    suffix = file_path.suffix
                    if suffix in language_extensions:
                        lang = language_extensions[suffix]
                        primary_languages[lang] = primary_languages.get(lang, 0) + 1
                    
                    # Check for sensitive files
                    filename = file_path.name
                    for pattern in self.SENSITIVE_PATTERNS:
                        if self._match_pattern(filename, pattern):
                            sensitive_files.append(str(file_path.relative_to(repo_path)))
                            break
            
            # Detect primary language
            primary_language = max(primary_languages.items(), key=lambda x: x[1])[0] if primary_languages else "Unknown"
            
            return RepositoryInfo(
                owner=owner,
                repo=repo,
                url=f"https://github.com/{owner}/{repo}",
                language=primary_language,
                files_count=files_count,
                total_lines=total_lines,
                primary_languages=primary_languages,
                sensitive_files=sensitive_files[:20],  # Limit to first 20
            )
            
        except Exception as e:
            logger.error(f"Error analyzing repository: {e}")
            return None
    
    @staticmethod
    def _match_pattern(filename: str, pattern: str) -> bool:
        """Check if filename matches a pattern.
        
        Args:
            filename: File name
            pattern: Pattern with wildcards
            
        Returns:
            True if matches
        """
        import fnmatch
        return fnmatch.fnmatch(filename, pattern)
    
    async def scan_repository(self, owner: str, repo: str) -> dict:
        """Full repository scan workflow.
        
        Args:
            owner: Repository owner
            repo: Repository name
            
        Returns:
            Scan results with repository info and files to scan
        """
        repo_path = await self.clone_repository(owner, repo)
        if not repo_path:
            return {
                "owner": owner,
                "repo": repo,
                "error": f"Failed to clone repository {owner}/{repo}",
                "files": []
            }
        
        repo_info = await self.analyze_repository(repo_path)
        if not repo_info:
            return {
                "owner": owner,
                "repo": repo,
                "error": "Failed to analyze repository",
                "files": []
            }
        
        # Collect files to scan
        files_to_scan = []
        supported_extensions = [".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".go", ".rs"]
        supported_file_names = ["requirements.txt", "package.json"]
        
        for file_path in repo_path.rglob("*"):
            if file_path.is_file():
                # Skip hidden and node_modules
                if any(part.startswith(".") for part in file_path.parts):
                    continue
                if any(part in ["node_modules", "__pycache__", "venv", ".venv"] for part in file_path.parts):
                    continue
                
                # Check extension or important manifest names
                if file_path.suffix in supported_extensions or file_path.name in supported_file_names:
                    try:
                        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()
                        
                        files_to_scan.append({
                            "path": str(file_path.relative_to(repo_path)),
                            "content": content,
                            "language": self._detect_language(file_path.suffix, file_path.name),
                            "size": len(content)
                        })
                    except Exception as e:
                        logger.warning(f"Could not read {file_path}: {e}")
        
        return {
            "owner": owner,
            "repo": repo,
            "url": repo_info.url,
            "language": repo_info.language,
            "files_count": repo_info.files_count,
            "total_lines": repo_info.total_lines,
            "languages": repo_info.primary_languages,
            "sensitive_files": repo_info.sensitive_files,
            "files": files_to_scan,
            "repo_path": str(repo_path)
        }
    
    @staticmethod
    def _detect_language(extension: str, filename: Optional[str] = None) -> str:
        """Detect language from file extension or manifest filename."""
        mapping = {
            ".py": "python",
            ".js": "javascript",
            ".ts": "typescript",
            ".tsx": "typescript",
            ".jsx": "javascript",
            ".java": "java",
            ".go": "go",
            ".rs": "rust",
        }
        if filename:
            if filename == "requirements.txt":
                return "python"
            if filename == "package.json":
                return "javascript"
        return mapping.get(extension, "unknown")
    
    async def cleanup_repository(self, repo_path: str) -> bool:
        """Clean up cloned repository.
        
        Args:
            repo_path: Path to cloned repository
            
        Returns:
            True if successful
        """
        try:
            path = Path(repo_path)
            if path.exists():
                shutil.rmtree(path)
                logger.info(f"Cleaned up {repo_path}")
                return True
        except Exception as e:
            logger.error(f"Error cleaning up {repo_path}: {e}")
        
        return False
    
    async def cleanup_all(self) -> None:
        """Clean up all temporary repositories."""
        try:
            if self.TEMP_DIR.exists():
                shutil.rmtree(self.TEMP_DIR)
                logger.info("Cleaned up all temporary repositories")
        except Exception as e:
            logger.error(f"Error cleaning up temp directory: {e}")
