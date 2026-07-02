"""
Sovereign Patch Agent — MCP Server (stdio transport)
=====================================================
Exposes domain-specific tools for vulnerability scanning, sandbox testing,
PR staging, vulnerability database queries, and audit log retrieval.
"""

import datetime
import json
import os
from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("sovereign-sandbox-tools")

AUDIT_LOG_PATH = Path(__file__).parent.parent / "audit_log.json"


def _read_audit_log() -> list:
    """Read the persistent audit log."""
    if AUDIT_LOG_PATH.exists():
        try:
            return json.loads(AUDIT_LOG_PATH.read_text())
        except (json.JSONDecodeError, OSError):
            return []
    return []


# ─────────────────────────────────────────────────────────────────────
# Tool 1: scan_codebase
# ─────────────────────────────────────────────────────────────────────

@mcp.tool()
def scan_codebase(
    code: str,
    language: str = "python",
    scan_depth: str = "standard",
) -> str:
    """Deep-scan a codebase or code snippet for known vulnerability patterns.

    Args:
        code: The source code to scan for vulnerabilities.
        language: Programming language of the code (default: python).
        scan_depth: Scan depth - 'quick', 'standard', or 'deep'.

    Returns:
        JSON string with scan results including found vulnerability patterns.
    """
    # Pattern-based vulnerability detection
    vuln_patterns = {
        "SQL_INJECTION": [
            r"execute\s*\(\s*[\"'].*%s",
            r"execute\s*\(\s*f[\"']",
            r"cursor\.execute\s*\(\s*[\"'].*\+",
        ],
        "COMMAND_INJECTION": [
            r"os\.system\s*\(",
            r"subprocess\.call\s*\(\s*[\"']",
            r"eval\s*\(",
            r"exec\s*\(",
        ],
        "HARDCODED_SECRETS": [
            r"(?:password|secret|api_key|token)\s*=\s*[\"'][^\"']{8,}[\"']",
            r"(?:AKIA|AIza|sk-|ghp_)[A-Za-z0-9]{10,}",
        ],
        "INSECURE_DESERIALIZATION": [
            r"pickle\.loads?\s*\(",
            r"yaml\.load\s*\(",
            r"marshal\.loads?\s*\(",
        ],
        "PATH_TRAVERSAL": [
            r"open\s*\(.*\+.*\)",
            r"os\.path\.join\s*\(.*request",
        ],
    }

    import re
    findings = []
    lines = code.split("\n")
    for vuln_type, patterns in vuln_patterns.items():
        for pattern in patterns:
            for i, line in enumerate(lines, 1):
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append({
                        "type": vuln_type,
                        "line": i,
                        "code": line.strip(),
                        "pattern": pattern,
                    })

    result = {
        "scan_id": f"SCAN-{datetime.datetime.now(datetime.UTC).strftime('%Y%m%d%H%M%S')}",
        "language": language,
        "depth": scan_depth,
        "lines_scanned": len(lines),
        "vulnerabilities_found": len(findings),
        "findings": findings,
        "status": "VULNERABILITIES_DETECTED" if findings else "CLEAN",
    }
    return json.dumps(result, indent=2)


# ─────────────────────────────────────────────────────────────────────
# Tool 2: run_sandbox_test
# ─────────────────────────────────────────────────────────────────────

@mcp.tool()
def run_sandbox_test(
    code: str,
    test_type: str = "safety",
) -> str:
    """Execute code validation in a sandboxed environment.
    Performs AST analysis and safety checks without actual execution.

    Args:
        code: The code to test in the sandbox.
        test_type: Type of test - 'safety', 'syntax', or 'full'.

    Returns:
        JSON string with sandbox test results.
    """
    import ast as ast_module

    results = {
        "test_type": test_type,
        "syntax_valid": False,
        "safety_check": "PENDING",
        "forbidden_imports": [],
        "dangerous_calls": [],
    }

    # Syntax check
    try:
        tree = ast_module.parse(code)
        results["syntax_valid"] = True
    except SyntaxError as e:
        results["syntax_valid"] = False
        results["syntax_error"] = str(e)
        results["safety_check"] = "FAILED"
        return json.dumps(results, indent=2)

    # Safety check — forbidden imports
    forbidden = {"os", "sys", "socket", "subprocess", "shutil", "ctypes"}
    for node in ast_module.walk(tree):
        if isinstance(node, (ast_module.Import, ast_module.ImportFrom)):
            module = node.module if isinstance(node, ast_module.ImportFrom) else None
            for alias in node.names:
                if alias.name in forbidden:
                    results["forbidden_imports"].append(alias.name)
            if module and module.split(".")[0] in forbidden:
                results["forbidden_imports"].append(module)

    # Dangerous function calls
    dangerous_calls = {"eval", "exec", "compile", "__import__", "globals", "locals"}
    for node in ast_module.walk(tree):
        if isinstance(node, ast_module.Call):
            if isinstance(node.func, ast_module.Name) and node.func.id in dangerous_calls:
                results["dangerous_calls"].append(node.func.id)

    if results["forbidden_imports"] or results["dangerous_calls"]:
        results["safety_check"] = "FAILED"
    else:
        results["safety_check"] = "PASSED"

    return json.dumps(results, indent=2)


# ─────────────────────────────────────────────────────────────────────
# Tool 3: stage_git_pull_request
# ─────────────────────────────────────────────────────────────────────

@mcp.tool()
def stage_git_pull_request(
    repo: str,
    branch: str,
    title: str,
    body: str,
) -> str:
    """Stage a pull request on GitHub via the GitHub API.

    Args:
        repo: GitHub repository in 'owner/repo' format.
        branch: Source branch name for the PR.
        title: Pull request title.
        body: Pull request description/body.

    Returns:
        JSON string with PR creation result or error.
    """
    token = os.getenv("GITHUB_TOKEN")
    if not token:
        return json.dumps({
            "status": "SIMULATED",
            "message": (
                "GITHUB_TOKEN not set — PR staged in simulation mode. "
                "Set GITHUB_TOKEN in .env for production GitHub integration."
            ),
            "pr_details": {
                "repo": repo,
                "branch": branch,
                "title": title,
                "body": body[:200],
                "simulated_url": f"https://github.com/{repo}/pull/SIMULATED",
            },
        }, indent=2)

    try:
        import requests
        headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json",
        }
        url = f"https://api.github.com/repos/{repo}/pulls"
        payload = {
            "title": title,
            "head": branch,
            "base": "main",
            "body": body,
        }
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()
        pr_data = response.json()
        return json.dumps({
            "status": "CREATED",
            "html_url": pr_data.get("html_url"),
            "number": pr_data.get("number"),
            "state": pr_data.get("state"),
        }, indent=2)
    except Exception as e:
        return json.dumps({
            "status": "ERROR",
            "error": str(e),
        }, indent=2)


# ─────────────────────────────────────────────────────────────────────
# Tool 4: get_vulnerability_db
# ─────────────────────────────────────────────────────────────────────

@mcp.tool()
def get_vulnerability_db(
    query: str,
    severity_filter: str = "ALL",
) -> str:
    """Query the vulnerability knowledge base for known CVEs and CWEs.

    Args:
        query: Search query (CVE ID, CWE ID, or keyword like 'sql injection').
        severity_filter: Filter by severity - 'ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'.

    Returns:
        JSON string with matching vulnerability entries.
    """
    # Built-in vulnerability knowledge base
    vuln_db = [
        {
            "id": "CWE-89", "name": "SQL Injection",
            "severity": "CRITICAL",
            "description": "Improper neutralization of special elements used in SQL commands.",
            "remediation": "Use parameterized queries or prepared statements.",
        },
        {
            "id": "CWE-78", "name": "OS Command Injection",
            "severity": "CRITICAL",
            "description": "Improper neutralization of special elements used in OS commands.",
            "remediation": "Use safe APIs instead of shell commands. Validate and sanitize inputs.",
        },
        {
            "id": "CWE-79", "name": "Cross-Site Scripting (XSS)",
            "severity": "HIGH",
            "description": "Improper neutralization of input during web page generation.",
            "remediation": "Encode output, use Content Security Policy headers.",
        },
        {
            "id": "CWE-502", "name": "Insecure Deserialization",
            "severity": "HIGH",
            "description": "Deserialization of untrusted data can result in code execution.",
            "remediation": "Use safe serialization formats like JSON. Validate before deserializing.",
        },
        {
            "id": "CWE-22", "name": "Path Traversal",
            "severity": "HIGH",
            "description": "Improper limitation of a pathname to a restricted directory.",
            "remediation": "Validate and canonicalize file paths. Use allowlists.",
        },
        {
            "id": "CWE-798", "name": "Hardcoded Credentials",
            "severity": "CRITICAL",
            "description": "Use of hard-coded credentials for authentication.",
            "remediation": "Use environment variables or secret managers.",
        },
        {
            "id": "CWE-327", "name": "Broken Cryptography",
            "severity": "MEDIUM",
            "description": "Use of a broken or risky cryptographic algorithm.",
            "remediation": "Use strong, modern algorithms (AES-256, SHA-256+).",
        },
    ]

    query_lower = query.lower()
    results = []
    for entry in vuln_db:
        if (query_lower in entry["id"].lower() or
                query_lower in entry["name"].lower() or
                query_lower in entry["description"].lower()):
            if severity_filter == "ALL" or entry["severity"] == severity_filter:
                results.append(entry)

    return json.dumps({
        "query": query,
        "severity_filter": severity_filter,
        "results_count": len(results),
        "results": results,
    }, indent=2)


# ─────────────────────────────────────────────────────────────────────
# Tool 5: get_audit_log
# ─────────────────────────────────────────────────────────────────────

@mcp.tool()
def get_audit_log(
    severity_filter: str = "ALL",
    last_n: int = 20,
) -> str:
    """Retrieve recent entries from the persistent audit log.

    Args:
        severity_filter: Filter by severity - 'ALL', 'INFO', 'WARNING', 'CRITICAL'.
        last_n: Number of most recent entries to return (default: 20).

    Returns:
        JSON string with audit log entries.
    """
    logs = _read_audit_log()
    if severity_filter != "ALL":
        logs = [entry for entry in logs if entry.get("severity") == severity_filter]
    logs = logs[-last_n:]
    return json.dumps({
        "total_entries": len(logs),
        "severity_filter": severity_filter,
        "entries": logs,
    }, indent=2)


# ─────────────────────────────────────────────────────────────────────
# MAIN (stdio transport)
# ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    mcp.run(transport="stdio")
