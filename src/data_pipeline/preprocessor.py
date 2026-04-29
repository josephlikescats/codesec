"""Code Preprocessor Module

Preprocesses code for ML model training and vulnerability detection.
"""

import re
import logging
from typing import Any, Optional
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class ProcessedCode:
    """Represents processed code with metadata."""
    original_code: str
    tokens: list[str]
    language: str
    file_path: Optional[str] = None
    line_count: int = 0
    has_vulnerability: bool = False
    vulnerability_type: Optional[str] = None


class CodePreprocessor:
    """Preprocesses code for ML model input."""
    
    # Common vulnerability patterns for labeling
    VULNERABILITY_PATTERNS = {
        "sql_injection": [
            r"execute\s*\(\s*['\"].*?%.*?['\"]",
            r"cursor\.execute\s*\(\s*f['\"]",
            r"f['\"].*?(?:SELECT|INSERT|UPDATE|DELETE).*?\{.*?\}",
            r"\.format\s*\(\s*.*?(?:SELECT|INSERT|UPDATE|DELETE)",
        ],
        "command_injection": [
            r"os\.system\s*\(",
            r"subprocess\.call\s*\(",
            r"subprocess\.run\s*\(",
            r"exec\s*\(",
            r"eval\s*\(",
        ],
        "path_traversal": [
            r"open\s*\(\s*.*?(?:path|filename|file).*?\+",
            r"\.join\s*\(\s*.*?request",
        ],
        "xss": [
            r"innerHTML\s*=",
            r"\.html\s*\(",
            r"dangerouslySetInnerHTML",
        ],
        "hardcoded_secret": [
            r"password\s*=\s*['\"][^'\"]+['\"]",
            r"api_key\s*=\s*['\"][^'\"]+['\"]",
            r"secret\s*=\s*['\"][^'\"]+['\"]",
            r"token\s*=\s*['\"][a-zA-Z0-9_-]{20,}['\"]",
        ],
        "xxe": [
            r"etree\.parse\s*\(",
            r"DOMParser\s*\(",
        ],
        "deserialization": [
            r"pickle\.loads\s*\(",
            r"yaml\.load\s*\(",
            r"unserialize\s*\(",
        ],
        "ssrf": [
            r"urllib\.request\s*\(",
            r"requests\.get\s*\(",
            r"curl_exec\s*\(",
        ],
        "idor": [
            r"filter_by\s*\(\s*id\s*=",
            r"\.get\s*\(\s*id\s*=",
        ],
        "auth_bypass": [
            r"if\s*\(\s*.*?==\s*['\"]",
            r"return\s+True\s*#.*?bypass",
        ]
    }
    
    # Language-specific comment patterns
    COMMENT_PATTERNS = {
        "python": {
            "single": "#",
            "multi_start": '"""',
            "multi_end": '"""',
        },
        "javascript": {
            "single": "//",
            "multi_start": "/*",
            "multi_end": "*/",
        },
        "java": {
            "single": "//",
            "multi_start": "/*",
            "multi_end": "*/",
        },
        "go": {
            "single": "//",
            "multi_start": "/*",
            "multi_end": "*/",
        },
        "rust": {
            "single": "//",
            "multi_start": "/*",
            "multi_end": "*/",
        },
    }
    
    def __init__(self, max_length: int = 512):
        self.max_length = max_length
    
    def preprocess(self, code: str, language: str = "python") -> ProcessedCode:
        """Preprocess code for model input."""
        # Remove comments
        clean_code = self._remove_comments(code, language)
        
        # Tokenize
        tokens = self._tokenize(clean_code, language)
        
        # Detect vulnerabilities
        vuln_type = self._detect_vulnerability_patterns(clean_code)
        
        return ProcessedCode(
            original_code=code,
            tokens=tokens,
            language=language,
            line_count=len(code.splitlines()),
            has_vulnerability=vuln_type is not None,
            vulnerability_type=vuln_type
        )
    
    def _remove_comments(self, code: str, language: str) -> str:
        """Remove comments from code."""
        patterns = self.COMMENT_PATTERNS.get(language, self.COMMENT_PATTERNS["python"])
        
        # Remove single-line comments
        single_comment = patterns["single"]
        for line in code.splitlines():
            if single_comment in line:
                comment_idx = line.index(single_comment)
                code = code[:code.index(line) + comment_idx] + code[code.index(line) + len(line):]
                break
        
        # Remove multi-line comments (simplified)
        if "multi_start" in patterns:
            multi_start = patterns["multi_start"]
            multi_end = patterns["multi_end"]
            if multi_start in code:
                # Simple removal - not perfect but good enough for preprocessing
                code = re.sub(rf'{re.escape(multi_start)}.*?{re.escape(multi_end)}', '', code, flags=re.DOTALL)
        
        return code
    
    def _tokenize(self, code: str, language: str) -> list[str]:
        """Tokenize code into meaningful units."""
        # Simple whitespace-based tokenization
        # In production, use proper language-specific tokenizers
        tokens = []
        
        # Split on whitespace and common delimiters
        words = re.split(r'[\s\n\r\t]+', code)
        
        for word in words:
            word = word.strip()
            if word:
                # Keep identifiers and keywords
                if re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', word):
                    tokens.append(word)
                # Keep operators and punctuation as-is
                elif re.match(r'^[^\w]+$', word):
                    tokens.append(word)
        
        # Truncate to max length
        return tokens[:self.max_length]
    
    def _detect_vulnerability_patterns(self, code: str) -> Optional[str]:
        """Detect vulnerability patterns in code."""
        for vuln_type, patterns in self.VULNERABILITY_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, code, re.IGNORECASE):
                    return vuln_type
        return None
    
    def extract_functions(self, code: str, language: str = "python") -> list[dict]:
        """Extract function definitions from code."""
        functions = []
        
        if language == "python":
            # Match function definitions
            pattern = r'def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\([^)]*\)\s*:'
            matches = re.finditer(pattern, code)
            
            for match in matches:
                func_name = match.group(1)
                start_pos = match.start()
                
                # Find the function body (simplified)
                lines_after = code[start_pos:].splitlines()[:20]
                func_code = "\n".join(lines_after)
                
                functions.append({
                    "name": func_name,
                    "start_line": code[:start_pos].count("\n") + 1,
                    "code": func_code
                })
        
        return functions
    
    def extract_classes(self, code: str, language: str = "python") -> list[dict]:
        """Extract class definitions from code."""
        classes = []
        
        if language == "python":
            pattern = r'class\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:\([^)]*\))?\s*:'
            matches = re.finditer(pattern, code)
            
            for match in matches:
                class_name = match.group(1)
                start_pos = match.start()
                
                lines_after = code[start_pos:].splitlines()[:30]
                class_code = "\n".join(lines_after)
                
                classes.append({
                    "name": class_name,
                    "start_line": code[:start_pos].count("\n") + 1,
                    "code": class_code
                })
        
        return classes
    
    def load_and_preprocess_file(self, file_path: str) -> ProcessedCode:
        """Load and preprocess a code file."""
        path = Path(file_path)
        
        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        # Detect language from extension
        language = self._detect_language(path.suffix)
        
        # Read file
        with open(path, "r", encoding="utf-8") as f:
            code = f.read()
        
        return self.preprocess(code, language)
    
    def _detect_language(self, extension: str) -> str:
        """Detect programming language from file extension."""
        language_map = {
            ".py": "python",
            ".js": "javascript",
            ".ts": "typescript",
            ".jsx": "javascript",
            ".tsx": "typescript",
            ".java": "java",
            ".go": "go",
            ".rs": "rust",
            ".c": "c",
            ".cpp": "cpp",
            ".cs": "csharp",
            ".rb": "ruby",
            ".php": "php",
        }
        return language_map.get(extension.lower(), "python")


# Example usage
def main():
    preprocessor = CodePreprocessor()
    
    # Test with vulnerable code
    vulnerable_code = '''
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return db.execute(query)
'''
    
    result = preprocessor.preprocess(vulnerable_code, "python")
    print(f"Language: {result.language}")
    print(f"Has vulnerability: {result.has_vulnerability}")
    print(f"Vulnerability type: {result.vulnerability_type}")
    print(f"Line count: {result.line_count}")
    print(f"Tokens: {result.tokens[:10]}...")


if __name__ == "__main__":
    main()