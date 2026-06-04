# Security Code Review Lab

A hands-on lab for identifying, classifying, and fixing **4 real-world web application vulnerabilities** embedded in a Python/Flask + HTML/JS app.

## Vulnerabilities

| ID | Category | CWE | Severity |
|---|---|---|---|
| V1 | SQL Injection | CWE-89 | Critical |
| V2 | Missing Input Validation | CWE-20 | High |
| V3 | Sensitive Data in localStorage | CWE-922 / CWE-312 | High |
| V4 | Client-Side Only Access Control | CWE-602 / CWE-285 | Critical |

## Quick Start

### GitHub Codespaces

[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/YOUR_ORG/security-lab)

The environment installs all dependencies and seeds the database automatically on startup.

### Local

```bash
# Install dependencies
pip install -r app/backend/requirements.txt -r requirements-dev.txt

# Init DB and run API
make run
```

Open `app/frontend/index.html` in your browser (or serve with `python -m http.server 8080 -d app/frontend`).

## Run Security Scans

```bash
# SAST (Bandit + Semgrep) — no running app needed
make sast

# DAST — requires the API to be running
make dast

# Both
make all
```

Reports are written to `reports/sast/` and `reports/dast/`.

## Lab Instructions

See [`lab/INSTRUCCIONES.md`](lab/INSTRUCCIONES.md).

## CI/CD Pipeline

The GitHub Actions workflow (`.github/workflows/security.yml`) runs on every push:

1. **Bandit** — Python AST-based security linter → SARIF uploaded to GitHub Security tab
2. **Semgrep** — semantic grep with OWASP Top-10 + JWT rules → SARIF
3. **CodeQL** — GitHub's native SAST engine
4. **Custom DAST probes** — HTTP-level tests against the running API

## Project Structure

```
.
├── .devcontainer/        # GitHub Codespaces config
├── .github/workflows/    # CI security pipeline
├── app/
│   ├── backend/          # Flask API (vulnerable)
│   └── frontend/         # SPA HTML+JS (vulnerable)
├── lab/
│   ├── INSTRUCCIONES.md  # Student guide (Spanish)
│   └── solucion/         # Instructor answer key
├── scripts/
│   ├── run_sast.sh       # Local SAST runner
│   └── run_dast.py       # Local DAST runner
├── Makefile
└── requirements-dev.txt  # Bandit, Semgrep, requests
```

## Credentials (lab only)

| Username | Password | Role |
|---|---|---|
| alice | alice123 | admin |
| bob | bob456 | user |
| carol | carol789 | user |
