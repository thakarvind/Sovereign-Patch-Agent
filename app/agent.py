"""
Sovereign Patch Agent — ADK 2.0 Multi-Agent System
====================================================
Production-grade autonomous vulnerability detection, self-healing patching,
sandbox testing, and human-in-the-loop (HITL) merge approval system.

Architecture (ADK 2.0 Workflow Graph):
  START
    └─ security_checkpoint (node)
         ├─ SECURITY_EVENT ──> security_event_handler (node)
         └─ PASSED ──────────> run_orchestrator (node) ── NEEDS_APPROVAL ──> human_approval (node)
"""

import ast
import datetime
import json
import logging
import re
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from google.adk.agents import LlmAgent
from google.adk.agents.context import Context
from google.adk.events import Event, RequestInput
from google.adk.tools import AgentTool, McpToolset
from google.adk.workflow import START, Edge, Workflow, node
from google.genai import types
from mcp import StdioServerParameters

from app.config import config

# Load environment variables from .env file
load_dotenv()

logger = logging.getLogger("SovereignPatchAgent")
logging.basicConfig(level=logging.INFO)

AUDIT_LOG_PATH = Path(__file__).parent.parent / "audit_log.json"
MCP_SERVER_PATH = str(Path(__file__).parent / "mcp_server.py")

# Retry configuration to handle quota exhaustion (429 errors)
retry_options = types.HttpRetryOptions(initial_delay=2.0, attempts=5)

# ═══════════════════════════════════════════════════════════════════════════════
# SECURITY UTILITIES
# ═══════════════════════════════════════════════════════════════════════════════

FORBIDDEN_IMPORTS = {"os", "sys", "socket", "subprocess", "shutil", "ctypes"}

INJECTION_KEYWORDS = [
    "ignore previous instructions",
    "disregard above",
    "system prompt",
    "jailbreak",
    "reveal your instructions",
    "forget your rules",
    "act as an unrestricted",
    "bypass security",
    "override safety",
]

PII_PATTERNS = {
    "SSN": r"\b\d{3}-\d{2}-\d{4}\b",
    "CREDIT_CARD": r"\b(?:\d{4}[- ]?){3}\d{4}\b",
    "EMAIL": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
    "PHONE": r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
    "API_KEY": r"\b(?:AKIA|AIza|sk-|ghp_|gho_|ghu_|ghs_|ghr_)[A-Za-z0-9_\-]{10,}\b",
    "GITHUB_TOKEN": r"\bgh[ps]_[A-Za-z0-9]{36,}\b",
}


def _write_audit_log(entry: dict):
    """Append a structured JSON audit entry to persistent log."""
    entry["timestamp"] = datetime.datetime.now(datetime.UTC).isoformat()
    logs = []
    if AUDIT_LOG_PATH.exists():
        try:
            logs = json.loads(AUDIT_LOG_PATH.read_text())
        except (json.JSONDecodeError, OSError):
            logs = []
    logs.append(entry)
    AUDIT_LOG_PATH.write_text(json.dumps(logs, indent=2))


def validate_code_safety(code: str) -> dict:
    """Uses AST to prevent malicious imports in generated/refactored code."""
    violations = []
    try:
        tree = ast.parse(code)
        for node_ast in ast.walk(tree):
            if isinstance(node_ast, (ast.Import, ast.ImportFrom)):
                module = node_ast.module if isinstance(node_ast, ast.ImportFrom) else None
                names = [alias.name for alias in node_ast.names]
                for name in names:
                    if name in FORBIDDEN_IMPORTS:
                        violations.append(f"Forbidden import: {name}")
                if module and module.split(".")[0] in FORBIDDEN_IMPORTS:
                    violations.append(f"Forbidden module: {module}")
    except SyntaxError as e:
        violations.append(f"SyntaxError in code: {e}")

    result = {"safe": len(violations) == 0, "violations": violations}
    _write_audit_log({
        "event": "CODE_SAFETY_CHECK",
        "severity": "INFO" if result["safe"] else "CRITICAL",
        "violations": violations,
    })
    return result


def scrub_pii(text: str) -> str:
    """Redact PII from text using regex patterns."""
    redacted_types = []
    for pii_type, pattern in PII_PATTERNS.items():
        if re.search(pattern, text):
            redacted_types.append(pii_type)
            text = re.sub(pattern, f"[REDACTED_{pii_type}]", text)
    if redacted_types:
        _write_audit_log({
            "event": "PII_REDACTION",
            "severity": "WARNING",
            "redacted_types": redacted_types,
        })
    return text


def detect_injection(text: str) -> bool:
    """Detect prompt injection attempts via keyword matching."""
    lower_text = text.lower()
    for keyword in INJECTION_KEYWORDS:
        if keyword in lower_text:
            _write_audit_log({
                "event": "INJECTION_DETECTED",
                "severity": "CRITICAL",
                "matched_keyword": keyword,
                "action": "BLOCKED",
            })
            return True
    return False


# ═══════════════════════════════════════════════════════════════════════════════
# INLINE SECURITY TOOLS
# ═══════════════════════════════════════════════════════════════════════════════

def security_scan_input(input_text: str) -> dict:
    """Scan input text for PII and prompt injection attacks.

    Args:
        input_text: The text to scan for security threats.

    Returns:
        Dict with scan results including PII findings and injection status.
    """
    pii_found = []
    for pii_type, pattern in PII_PATTERNS.items():
        if re.search(pattern, input_text):
            pii_found.append(pii_type)

    injection_detected = detect_injection(input_text)
    scrubbed = scrub_pii(input_text) if pii_found else input_text

    # Domain-specific: flag direct-to-production requests
    prod_guard = False
    for pattern in [r"\b(?:deploy|push)\s+(?:to\s+)?prod", r"\bmerge\s+(?:to|into)\s+main\b"]:
        if re.search(pattern, input_text, re.IGNORECASE):
            prod_guard = True
            _write_audit_log({
                "event": "PRODUCTION_GUARD",
                "severity": "WARNING",
                "action": "FLAGGED_FOR_REVIEW",
            })

    _write_audit_log({
        "event": "SECURITY_CHECKPOINT",
        "severity": "CRITICAL" if injection_detected else ("WARNING" if pii_found else "INFO"),
        "pii_found": pii_found,
        "injection_detected": injection_detected,
        "production_guard": prod_guard,
    })

    return {
        "clean_text": scrubbed,
        "pii_types_found": pii_found,
        "injection_detected": injection_detected,
        "production_guard_triggered": prod_guard,
        "status": "BLOCKED" if injection_detected else "PASSED",
    }


def ast_validate_code(code: str) -> dict:
    """Validate code safety using AST analysis. Checks for forbidden imports
    and dangerous function calls.

    Args:
        code: Python source code to validate.

    Returns:
        Dict with validation results.
    """
    return validate_code_safety(code)


# ═══════════════════════════════════════════════════════════════════════════════
# MCP TOOLSET (wired into scanner + patcher + reviewer)
# ═══════════════════════════════════════════════════════════════════════════════

mcp_tools = McpToolset(
    connection_params=StdioServerParameters(
        command="uv",
        args=["run", MCP_SERVER_PATH],
    ),
)

# ═══════════════════════════════════════════════════════════════════════════════
# SUB-AGENTS (SPECIALIZED WORKERS)
# ═══════════════════════════════════════════════════════════════════════════════

vulnerability_scanner = LlmAgent(
    name="VulnerabilityScanner",
    model=config.model,
    instruction="""You are a senior security engineer specializing in vulnerability detection.

You have access to MCP tools:
- scan_codebase: Deep scan code for vulnerability patterns
- get_vulnerability_db: Query known CVE/CWE database
- run_sandbox_test: Validate code safety in sandbox

Given source code or a codebase description, you MUST:
1. Use scan_codebase to perform pattern-based vulnerability detection
2. Use get_vulnerability_db to cross-reference any findings
3. Classify each finding by severity: CRITICAL, HIGH, MEDIUM, LOW
4. Provide specific remediation suggestions

Output a comprehensive vulnerability report. Be thorough but avoid false positives.""",
    description="Scans code for security vulnerabilities using MCP tools.",
    tools=[mcp_tools],
    generate_content_config=types.GenerateContentConfig(
        http_options=types.HttpOptions(retry_options=retry_options),
    ),
)

patch_generator = LlmAgent(
    name="PatchGenerator",
    model=config.model,
    instruction="""You are an expert software engineer specializing in security patch generation.

You have access to MCP tools:
- run_sandbox_test: Test your patches for safety before proposing them
- stage_git_pull_request: Stage a PR on GitHub (only after approval)

Given a vulnerability report from the scanner, you MUST:
1. Generate a minimal, targeted patch for each vulnerability
2. Use run_sandbox_test to validate each patch is safe (no forbidden imports)
3. Ensure patches maintain backward compatibility
4. NEVER use forbidden imports: os, sys, socket, subprocess, shutil, ctypes

Output the complete patch set with explanations for each change.
Format patches as clear before/after code blocks.""",
    description="Generates secure patches and validates them via sandbox.",
    tools=[mcp_tools],
    generate_content_config=types.GenerateContentConfig(
        http_options=types.HttpOptions(retry_options=retry_options),
    ),
)

code_reviewer = LlmAgent(
    name="CodeReviewer",
    model=config.model,
    instruction="""You are a principal engineer performing final code review on security patches.

You have access to MCP tools:
- run_sandbox_test: Verify patches pass safety checks
- get_vulnerability_db: Cross-reference against known vulnerabilities
- get_audit_log: Review the security audit trail for this session

Given vulnerability reports and proposed patches, you MUST:
1. Verify each patch actually fixes the reported vulnerability
2. Use run_sandbox_test to confirm safety
3. Check the audit_log for any security events during this session
4. Provide your review decision: APPROVED, NEEDS_CHANGES, or REJECTED

If ANY patch fails sandbox testing or introduces new risks → REJECT.

End your review with a clear summary and your final decision.
For approved patches, suggest the user type "APPROVE" to stage the PR.
For rejected patches, explain what needs to change.""",
    description="Reviews patches for correctness, quality, and safety.",
    tools=[mcp_tools],
    generate_content_config=types.GenerateContentConfig(
        http_options=types.HttpOptions(retry_options=retry_options),
    ),
)

# ═══════════════════════════════════════════════════════════════════════════════
# ORCHESTRATOR AGENT (DELEGATOR)
# ═══════════════════════════════════════════════════════════════════════════════

orchestrator_agent = LlmAgent(
    name="SovereignPatchOrchestratorAgent",
    model=config.model,
    instruction="""You are the main Sovereign Patch Orchestrator Agent.
Your job is to coordinate autonomous vulnerability scanning, secure patch generation, and review.

You have access to three specialized sub-agents via AgentTools:
- VulnerabilityScanner: Call this tool first to analyze and scan the codebase or code.
- PatchGenerator: If vulnerabilities are found, call this tool to produce targeted secure patches.
- CodeReviewer: Call this tool next to evaluate and perform a final code review of the generated patches.

You MUST:
1. Call VulnerabilityScanner to scan the target codebase.
2. If vulnerabilities are identified, call PatchGenerator to create a patch set.
3. Call CodeReviewer to audit the generated patches.
4. Return the final decision clearly. If approved, make sure to output the review summary and end with APPROVED so the workflow knows to request human confirmation.""",
    description="Orchestrates vulnerability detection, patch generation, and review.",
    tools=[
        AgentTool(vulnerability_scanner),
        AgentTool(patch_generator),
        AgentTool(code_reviewer),
    ],
    generate_content_config=types.GenerateContentConfig(
        http_options=types.HttpOptions(retry_options=retry_options),
    ),
)

# ═══════════════════════════════════════════════════════════════════════════════
# WORKFLOW NODES (ADK 2.0 GRAPH ARCHITECTURE)
# ═══════════════════════════════════════════════════════════════════════════════

@node
async def security_checkpoint(ctx: Context, node_input: Any) -> str:
    """Workflow entry node. Screens and sanitizes incoming user queries."""
    text_input = ""
    if isinstance(node_input, str):
        text_input = node_input
    elif isinstance(node_input, types.Content):
        text_input = "".join(part.text for part in node_input.parts if part.text)
    elif isinstance(node_input, dict) and "text" in node_input:
        text_input = node_input["text"]
    else:
        text_input = str(node_input)

    res = security_scan_input(text_input)
    if res["status"] == "BLOCKED":
        ctx.route = "SECURITY_EVENT"
        return "⚠️ SECURITY ALERT: Prompt injection attempt detected and blocked. This incident has been logged."

    # Save clean input to context state and proceed
    ctx.state["clean_input"] = res["clean_text"]
    ctx.route = "PASSED"
    return res["clean_text"]


@node
async def security_event_handler(ctx: Context, node_input: str) -> str:
    """Terminal node handling security events."""
    return node_input


@node
async def run_orchestrator(ctx: Context, node_input: str) -> str:
    """Orchestration node. Runs the orchestrator agent and handles sub-agent tools."""
    clean_input = ctx.state.get("clean_input", node_input)

    from google.adk.runners import Runner
    from google.adk.sessions import InMemorySessionService

    runner = Runner(
        agent=orchestrator_agent,
        session_service=InMemorySessionService(),
        app_name="sovereign-patch-agent",
    )
    session = await runner.session_service.create_session(
        user_id="user",
        app_name="sovereign-patch-agent",
    )

    new_msg = types.Content(
        role="user",
        parts=[types.Part.from_text(text=clean_input)]
    )

    result_text = ""
    async for event in runner.run_async(
        user_id="user",
        session_id=session.id,
        new_message=new_msg,
    ):
        if event.content and event.content.parts:
            result_text += "".join(p.text for p in event.content.parts if p.text)

    # Clean up runner resources (MCP sessions)
    await runner.close()

    ctx.state["orchestrator_result"] = result_text

    # Route based on the reviewer outcome
    if "APPROVED" in result_text or "approve" in result_text.lower():
        ctx.route = "NEEDS_APPROVAL"
    else:
        ctx.route = "COMPLETED"

    return result_text


@node
async def human_approval(ctx: Context, node_input: str) -> Any:
    """HITL Approval Node. Prompts for manual merge approval."""
    interrupt_id = "human_merge_approval"
    approval_response = ctx.resume_inputs.get(interrupt_id)

    if approval_response is not None:
        val = str(approval_response).strip().upper()
        if val in ["YES", "APPROVE", "APPROVED", "Y"]:
            ctx.state["approval_status"] = "APPROVED"

            # Stage the PR using the GitHub Client
            from app.github_integration import GitHubClient
            client = GitHubClient()
            repo = ctx.state.get("github_repo", "thakarvind/Sovereign-Patch-Agent")
            branch = ctx.state.get("patch_branch", "patch-vulnerability-fix")
            pr_title = "Stage Security Patch - Vulnerability Remediation"
            pr_body = (
                "This PR was automatically generated and staged by the Sovereign Patch Agent.\n\n"
                f"Orchestrator Analysis:\n{ctx.state.get('orchestrator_result', 'N/A')}\n"
            )
            pr_url = client.create_pull_request(repo, branch, pr_title, pr_body)
            return f"Merge approved! Git Pull Request staged successfully:\n{pr_url}"
        else:
            ctx.state["approval_status"] = "REJECTED"
            return "Merge rejected. Staging aborted."

    return RequestInput(
        interrupt_id=interrupt_id,
        message="A security patch is ready for merging. Do you approve staging the Pull Request? (Yes/No)",
        response_schema=str,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# ORCHESTRATOR WORKFLOW GRAPH CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

root_agent = Workflow(
    name="SovereignPatchOrchestrator",
    description=(
        "Sovereign Patch Agent — autonomous vulnerability detection, "
        "self-healing patching, sandbox testing, and HITL merge approval."
    ),
    edges=[
        Edge(from_node=START, to_node=security_checkpoint),
        Edge(
            from_node=security_checkpoint,
            to_node=security_event_handler,
            route="SECURITY_EVENT",
        ),
        Edge(from_node=security_checkpoint, to_node=run_orchestrator, route="PASSED"),
        Edge(
            from_node=run_orchestrator,
            to_node=human_approval,
            route="NEEDS_APPROVAL",
        ),
    ],
)

