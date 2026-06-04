#!/usr/bin/env python3
"""
run_dast.py — Dynamic Application Security Testing
Probes the running API for each of the 4 lab vulnerabilities.

Usage:
    # start the backend first
    python app/backend/init_db.py
    python app/backend/app.py &

    # then run the scanner
    python scripts/run_dast.py [--url http://localhost:5000]
"""

import argparse
import json
import os
import sys
from dataclasses import dataclass, field
from typing import Callable

import requests

# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    vuln_id: str
    title: str
    cwe: str
    severity: str
    evidence: str
    passed: bool


# ---------------------------------------------------------------------------
# Probe helpers
# ---------------------------------------------------------------------------

def probe_sqli_login(base: str) -> Finding:
    """Vuln 1 — SQL Injection in /api/login via string concatenation."""
    # Classic tautology bypass: username = ' OR '1'='1' --
    payload = {"username": "' OR '1'='1' -- ", "password": "anything"}
    r = requests.post(f"{base}/api/login", json=payload, timeout=5)

    exploited = r.status_code == 200 and "token" in r.text
    return Finding(
        vuln_id  = "V1",
        title    = "SQL Injection — login endpoint",
        cwe      = "CWE-89",
        severity = "CRITICAL",
        evidence = (
            f"POST /api/login  payload={json.dumps(payload)}\n"
            f"  → HTTP {r.status_code}  body={r.text[:200]}"
        ),
        passed   = not exploited,
    )


def probe_type_validation(base: str) -> Finding:
    """Vuln 2 — Missing type validation on /api/user?id=."""
    # Non-numeric id should either fail or be rejected — never reach the DB.
    payloads = [
        "abc",            # non-numeric string
        "1 OR 1=1",       # SQL fragment
        "1; DROP TABLE users --",
    ]
    triggered = []
    for p in payloads:
        try:
            r = requests.get(f"{base}/api/user", params={"id": p}, timeout=5)
            if r.status_code == 500 or "OperationalError" in r.text or "sqlite" in r.text.lower():
                triggered.append((p, r.status_code, r.text[:100]))
            elif r.status_code == 200 and "username" in r.text:
                triggered.append((p, r.status_code, r.text[:100]))
        except Exception as e:
            triggered.append((p, "ERROR", str(e)))

    evidence_lines = [f"  payload={repr(p)}  → {s}  {t}" for p, s, t in triggered]
    return Finding(
        vuln_id  = "V2",
        title    = "Missing Input Validation — /api/user?id=",
        cwe      = "CWE-20",
        severity = "HIGH",
        evidence = "GET /api/user?id=<payload>\n" + "\n".join(evidence_lines) if triggered
                   else "GET /api/user?id=<non-numeric> — all rejected (OK)",
        passed   = len(triggered) == 0,
    )


def probe_unauth_admin(base: str) -> Finding:
    """Vuln 4 — Broken access control: /api/admin/users requires no token."""
    r = requests.get(f"{base}/api/admin/users", timeout=5)
    exposed = r.status_code == 200 and "users" in r.text

    return Finding(
        vuln_id  = "V4",
        title    = "Broken Access Control — /api/admin/users (no auth)",
        cwe      = "CWE-602 / CWE-285",
        severity = "CRITICAL",
        evidence = (
            f"GET /api/admin/users  (no Authorization header)\n"
            f"  → HTTP {r.status_code}  body={r.text[:300]}"
        ),
        passed   = not exposed,
    )


def probe_admin_delete(base: str) -> Finding:
    """Bonus: DELETE /api/admin/delete/<id> also has no auth check."""
    # Use a non-existent id to avoid actually deleting data
    r = requests.delete(f"{base}/api/admin/delete/9999", timeout=5)
    exposed = r.status_code in (200, 404) and r.status_code != 401

    return Finding(
        vuln_id  = "V4b",
        title    = "Broken Access Control — DELETE /api/admin/delete/:id (no auth)",
        cwe      = "CWE-285",
        severity = "CRITICAL",
        evidence = (
            f"DELETE /api/admin/delete/9999  (no Authorization header)\n"
            f"  → HTTP {r.status_code}  body={r.text[:200]}"
        ),
        passed   = not exposed,
    )


# ---------------------------------------------------------------------------
# Note on Vuln 3 (localStorage token) — static/manual check
# ---------------------------------------------------------------------------

def note_localstorage() -> Finding:
    """Vuln 3 — localStorage token storage (requires browser/manual review)."""
    return Finding(
        vuln_id  = "V3",
        title    = "Sensitive Data in localStorage — auth token",
        cwe      = "CWE-922 / CWE-312",
        severity = "HIGH",
        evidence  = (
            "app/frontend/index.html line ~71:\n"
            "  localStorage.setItem('auth_token', data.token);\n\n"
            "  DAST cannot observe browser storage automatically.\n"
            "  Detected by SAST / manual code review."
        ),
        passed   = False,   # known-vulnerable; flag always
    )


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

PROBES: list[Callable] = [
    probe_sqli_login,
    probe_type_validation,
    probe_unauth_admin,
    probe_admin_delete,
]

SEVERITY_ICON = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}


def run(base_url: str) -> None:
    sep = "=" * 60
    print(f"\n{sep}")
    print(" DAST — Dynamic Application Security Testing")
    print(f" Target: {base_url}")
    print(sep)

    findings: list[Finding] = []

    for probe in PROBES:
        try:
            f = probe(base_url)
        except requests.exceptions.ConnectionError:
            print(f"\n[ERROR] Cannot connect to {base_url}")
            print("        Is the backend running?  python app/backend/app.py")
            sys.exit(1)
        findings.append(f)

    # localStorage is a static finding
    findings.append(note_localstorage())

    # ---- Print report --------------------------------------------------------
    print()
    passed = sum(1 for f in findings if f.passed)
    failed = len(findings) - passed

    for f in findings:
        icon  = SEVERITY_ICON.get(f.severity, "⚪")
        state = "PASS ✅" if f.passed else "FAIL ❌"
        print(f"{sep}")
        print(f" [{f.vuln_id}] {icon} {f.title}")
        print(f"       CWE: {f.cwe}   Severity: {f.severity}   Result: {state}")
        print()
        for line in f.evidence.splitlines():
            print(f"  {line}")
        print()

    print(sep)
    print(f" Summary: {failed} vulnerabilities confirmed / {passed} checks passed")
    print(sep)

    # ---- Save JSON report ----------------------------------------------------
    os.makedirs("reports/dast", exist_ok=True)
    report_path = "reports/dast/dast_report.json"
    with open(report_path, "w") as fh:
        json.dump(
            [
                {
                    "vuln_id":  f.vuln_id,
                    "title":    f.title,
                    "cwe":      f.cwe,
                    "severity": f.severity,
                    "evidence": f.evidence,
                    "passed":   f.passed,
                }
                for f in findings
            ],
            fh,
            indent=2,
        )
    print(f"\n Report saved: {report_path}\n")

    sys.exit(1 if failed > 0 else 0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Lab DAST runner")
    parser.add_argument("--url", default="http://localhost:5000", help="Base URL of the API")
    args = parser.parse_args()
    run(args.url)
