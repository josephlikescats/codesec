# CodeSec - AI-Powered DevSecOps Security Scanner

CodeSec is an AI-first DevSecOps platform for scanning source code, GitHub repositories, and CI/CD pipelines for security issues. It combines pattern-based vulnerability checks, secret detection, dependency analysis, and optional ML-powered classification into a unified developer workflow.

## What this project does

- **Scan local code or pasted snippets** for vulnerabilities using heuristic rules
- **Clone and scan GitHub repositories** directly from `owner/repo` or GitHub URLs
- **Detect sensitive files** and repository metadata during repo scans
- **Scan dependencies** in `requirements.txt` and `package.json`
- **Optional ML support** using zero-shot classification when `transformers` and `torch` are installed
- **React dashboard** for easy UI-based scanning and reporting

## What is novel here

- A full GitHub repo cloning scanner integrated with a frontend dashboard
- Combined static vulnerability detection, secret scanning, and dependency checking
- Optional ML classifier layered on top of pattern-based detection
- Windows-safe repo clone cleanup and `.git` removal logic
- A simple, usable demo repository for showing scan behavior

## Quick Start

### Backend

```bash
git clone https://github.com/josephlikescats/codesec.git
cd codesec
python -m venv .venv
.venv\Scripts\activate
pip install -e .
uvicorn src.api.main:app --reload --host 127.0.0.1 --port 8000
```

Open the API docs at `http://127.0.0.1:8000/docs`.

### Frontend

```bash
cd src/web
npm install
npm run build
npm run preview -- --host 127.0.0.1 --port 5173
```

Open `http://127.0.0.1:5173` in your browser.

## GitHub repository scan

Use the endpoint `/api/v1/scan/github` to scan a GitHub repo:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/scan/github \
  -H "Content-Type: application/json" \
  -d '{"owner":"octocat", "repo":"Hello-World"}'
```

This will:
- clone `https://github.com/octocat/Hello-World.git`
- analyze repository contents
- scan supported source files
- return metadata, sensitive file findings, and vulnerability reports

## Local demo repository

A sample demo repo is included at `sample_repos/demo-scan-repo` to demonstrate the GitHub scanning workflow locally.

## Project layout

```
codesec/
├── sample_repos/        # Demo repo for scanner testing
├── src/
│   ├── api/              # FastAPI endpoints and server
│   ├── models/           # Detection, remediation, and ML logic
│   ├── integrations/     # GitHub repo scanner and CI helpers
│   ├── web/              # React dashboard UI
│   └── data_pipeline/    # CVE ingestion and repo scraping
├── tests/                # Test suite
├── pyproject.toml        # Packaging and dependencies
└── README.md             # Project overview
```

## Notes

- The backend can run without ML dependencies; it will use pattern-based detection if `transformers` or `torch` are unavailable.
- Install `httpx` to enable GitHub repository scanning if not already present.
- The frontend uses Vite with a proxy to connect to the backend during development.
- Use `pytest` to validate the scanner and application behavior.

## License

MIT License
