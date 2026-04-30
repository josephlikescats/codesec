# SecureCode AI - AI-Driven DevSecOps Platform

An AI-powered platform that automatically generates security tests, detects vulnerabilities, and suggests code fixes using ML models trained on CVE data and GitHub vulnerability reports.

## Features

- **Vulnerability Detection**: ML-powered scanning for security issues in code
- **Automated Test Generation**: AI-generated unit tests targeting detected vulnerabilities
- **Remediation Suggestions**: Context-aware code fixes for security issues
- **CI/CD Integration**: Seamless integration with GitHub Actions, Jenkins, and GitLab CI
- **Explainable AI**: XAI-powered explanations for vulnerability findings
- **Continuous Learning**: Feedback loop from production to improve detection

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     SecureCode AI Platform                      │
├─────────────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐ │
│  │   Code In    │  │  Vulnerability│  │   Test Generation    │ │
│  │   Scanner    │──│   Detector    │──│      Engine          │ │
│  └──────────────┘  └──────────────┘  └──────────────────────┘ │
│         │                  │                    │              │
│         ▼                  ▼                    ▼              │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │              ML Model Layer (CodeBERT/GPT)               │  │
│  └──────────────────────────────────────────────────────────┘  │
│         │                  │                    │              │
│         ▼                  ▼                    ▼              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐ │
│  │   CVE Data    │  │  GitHub       │  │   OWASP              │ │
│  │   Pipeline    │  │  Issues       │  │   Knowledge Base     │ │
│  └──────────────┘  └──────────────┘  └──────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/securecode-ai/securecode-ai.git
cd securecode-ai

# Install dependencies
pip install -e ".[dev]"

# Set up environment variables
cp .env.example .env
```

### Running the API Server

```bash
# Start the API server
uvicorn src.api.main:app --reload

# The API will be available at http://localhost:8000
# API documentation at http://localhost:8000/docs
```

### Using the Scanner

```bash
# Scan a file for vulnerabilities
curl -X POST http://localhost:8000/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"code": "def vulnerable_function(pwd): os.system(pwd)", "language": "python"}'
```

## Project Structure

```
securecode-ai/
├── src/
│   ├── api/              # FastAPI server and endpoints
│   ├── data_pipeline/   # CVE fetcher, GitHub scraper
│   ├── models/          # ML models for vulnerability detection
│   ├── integrations/    # CI/CD integration modules
│   └── web/             # React dashboard
├── tests/                # Test suite
├── config/               # Configuration files
└── pyproject.toml        # Project configuration
```

## API Endpoints

### Scanner API
- `POST /api/v1/scan` - Scan code for vulnerabilities
- `GET /api/v1/scan/{id}` - Get scan results

### Test Generation API
- `POST /api/v1/tests/generate` - Generate security tests
- `GET /api/v1/tests/{id}` - Get generated tests

### Remediation API
- `POST /api/v1/fix/suggest` - Get fix suggestions
- `POST /api/v1/fix/apply` - Apply suggested fix

## Configuration

Environment variables can be configured in `.env`:

```env
# Database
DATABASE_URL=postgresql://user:pass@localhost:5432/securecode
REDIS_URL=redis://localhost:6379/0

# ML Model
MODEL_PATH=models/securecode-v1
MODEL_DEVICE=cpu

# API
API_HOST=0.0.0.0
API_PORT=8000

# GitHub Integration
GITHUB_TOKEN=your_github_token
```

## Development

```bash
# Run tests
pytest

# Run with coverage
pytest --cov=src

# Lint code
ruff check src/

# Format code
black src/
```

## License

MIT License - see [LICENSE](LICENSE) for details.
Demo scan trigger
