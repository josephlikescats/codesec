# CodeSec - AI-Powered DevSecOps Security Scanner

CodeSec is an AI-first DevSecOps platform for scanning source code, GitHub repositories, and CI/CD pipelines for security issues. It combines pattern-based checks, secret detection, dependency analysis, and optional ML-powered vulnerability classification into a single developer workflow.

## Key capabilities

- **Code vulnerability scanning** using pattern matching and heuristic rules
- **GitHub repository scanning** for repository files, sensitive file detection, and metadata collection
- **Secret scanning** to identify hardcoded credentials and tokens
- **Dependency analysis** for insecure or suspicious manifest entries
- **CI/CD integration helpers** for Jenkins and GitLab pipelines
- **React-based dashboard** for paste, upload, and repo scan workflows

## Quick Start

### Install

```bash
git clone https://github.com/josephlikescats/codesec.git
cd codesec
python -m venv .venv
.venv\Scripts\activate
pip install -e .
```

### Run the backend

```bash
uvicorn src.api.main:app --reload --host 127.0.0.1 --port 8000
```

Open the API docs at `http://127.0.0.1:8000/docs`.

### Run the frontend

```bash
cd src/web
npm install
npm run build
cd ../../
python -m http.server 5173 --bind 127.0.0.1 --directory src/web/dist
```

Open `http://127.0.0.1:5173` in your browser.

### Example scan request

```bash
curl -X POST http://127.0.0.1:8000/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"code":"def vulnerable(): os.system(\"id\")", "language":"python"}'
```

## Project layout

```
codesec/
├── src/
│   ├── api/              # FastAPI endpoints and server
│   ├── models/           # Detection, remediation, and ML logic
│   ├── integrations/     # CI/CD and repo scan helpers
│   ├── web/              # React dashboard UI
│   └── data_pipeline/    # CVE ingestion and repo scraping
├── tests/                # Test suite
├── pyproject.toml        # Packaging and dependencies
└── README.md             # Project overview
```

## Notes

- The backend is designed to continue working even when optional ML dependencies are not installed.
- Install `httpx` and configure `GITHUB_TOKEN` to enable GitHub repository scanning.
- Use `pytest` to run tests and validate functionality.

## License

MIT License
