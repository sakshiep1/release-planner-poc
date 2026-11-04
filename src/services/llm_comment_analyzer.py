"""LLM-powered ChaiBot comment analyzer using the Cursor SDK.

Replaces the regex-based parser with an LLM call via ``cursor-sdk``
``Agent.prompt()`` to extract structured CVE triage data from ChaiBot
(oape_cve) Jira comments.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re

from cursor_sdk import Agent, AgentOptions, LocalAgentOptions, CursorAgentError

from src.core.config import get_settings

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """\
You are a CVE triage classifier for Red Hat cert-manager z-stream releases.
You will receive a ChaiBot (oape_cve) analysis comment from a Jira vulnerability ticket.

Analyze the comment and return ONLY a valid JSON object with these fields:

{
  "verdict": "<NOT_VULNERABLE | NOT_APPLICABLE | NEEDS_REVIEW | LOW | MEDIUM | HIGH | CRITICAL | AFFECTED>",
  "fix_type": "<VERSION_BUMP | TRIVIAL_BACKPORT | NON_TRIVIAL_BACKPORT | NOT_APPLICABLE | NEEDS_REVIEW>",
  "remediation_fix": "<exact remediation recommendation from the Remediation decision section, or empty string>",
  "dependency_type": "<direct | indirect | transitive | third_party_product | vendored | unknown>",
  "current_version": "<version currently used, or empty string>",
  "fixed_version": "<upstream version containing the fix, or null>",
  "symbol_reachable": <true | false>,
  "go_vuln_id": "<GO-XXXX-XXXX or null>",
  "ghsa_id": "<GHSA-xxxx-xxxx-xxxx or null>",
  "module": "<affected Go module path or container image path>",
  "description": "<2-3 sentence summary of the vulnerability and its impact on cert-manager>"
}

Classification rules for fix_type:
- VERSION_BUMP: fix is a simple dependency version bump or Go builder rebuild
- TRIVIAL_BACKPORT: a small cherry-pick or sustaining backport is needed
- NON_TRIVIAL_BACKPORT: complex backport, sustaining fork patch, or significant code change
- NOT_APPLICABLE: the product is not vulnerable, symbols are not reachable, or it is a false positive
- NEEDS_REVIEW: there is insufficient information to classify, or human review is explicitly required

For remediation_fix: extract the exact text from the "Remediation decision" section of the comment.
If no such section exists, summarize what action is recommended.

Return ONLY the JSON object. No markdown code fences, no explanation text, no commentary.
"""

_JSON_BLOCK_RE = re.compile(r"```(?:json)?\s*\n(.*?)\n```", re.DOTALL)
_BARE_JSON_RE = re.compile(r"\{[\s\S]*\}")

DEFAULT_RESULT: dict = {
    "verdict": "NEEDS_REVIEW",
    "fix_type": "NEEDS_REVIEW",
    "remediation_fix": "",
    "dependency_type": "unknown",
    "current_version": "",
    "fixed_version": None,
    "symbol_reachable": False,
    "go_vuln_id": None,
    "ghsa_id": None,
    "module": "",
    "description": "",
    "has_analysis": False,
}


def _parse_llm_json(text: str) -> dict | None:
    """Extract the first JSON object from LLM response text."""
    m = _JSON_BLOCK_RE.search(text)
    if m:
        try:
            return json.loads(m.group(1))
        except json.JSONDecodeError:
            pass
    m = _BARE_JSON_RE.search(text)
    if m:
        try:
            return json.loads(m.group(0))
        except json.JSONDecodeError:
            pass
    return None


def _build_prompt(comment_text: str, ticket_summary: str, ticket_image: str) -> str:
    """Build the user prompt sent to the Cursor agent."""
    parts = [SYSTEM_PROMPT, "\n---\n"]
    if ticket_summary:
        parts.append(f"Ticket title: {ticket_summary}\n")
    if ticket_image:
        parts.append(f"Affected image: {ticket_image}\n")
    parts.append("\nChaiBot comment:\n")
    parts.append(comment_text)
    return "\n".join(parts)


def _call_agent_sync(prompt: str, api_key: str, model: str) -> str:
    """Blocking call to Cursor SDK Agent.prompt(). Meant to run in a thread."""
    from pathlib import Path
    cwd = str(Path(__file__).resolve().parents[2])
    result = Agent.prompt(
        prompt,
        AgentOptions(
            api_key=api_key,
            model=model,
            local=LocalAgentOptions(cwd=cwd),
        ),
    )
    if result.status == "finished":
        return result.result
    logger.warning("Agent run status=%s for prompt (first 80 chars): %s", result.status, prompt[:80])
    return result.result or ""


async def analyze_chaibot_comment(
    comment_text: str,
    ticket_summary: str = "",
    ticket_image: str = "",
) -> dict:
    """Analyze a ChaiBot comment via LLM and return structured triage data.

    Falls back to DEFAULT_RESULT on any failure so callers always get a dict.
    """
    settings = get_settings()
    api_key = settings.scanner.cursor_api_key or os.environ.get("CURSOR_API_KEY", "")
    model = settings.scanner.cursor_model or "composer-2.5"

    if not api_key:
        logger.error("No Cursor API key configured — cannot run LLM analysis")
        return {**DEFAULT_RESULT, "description": "LLM analysis skipped: no API key"}

    prompt = _build_prompt(comment_text, ticket_summary, ticket_image)

    try:
        raw_response = await asyncio.to_thread(_call_agent_sync, prompt, api_key, model)
    except CursorAgentError as exc:
        logger.error("Cursor SDK agent error: %s (retryable=%s)", exc.message, exc.is_retryable)
        return {**DEFAULT_RESULT, "description": f"LLM error: {exc.message}"}
    except Exception:
        logger.exception("Unexpected error calling Cursor SDK agent")
        return {**DEFAULT_RESULT, "description": "LLM analysis failed unexpectedly"}

    if not raw_response:
        logger.warning("Empty response from Cursor agent")
        return {**DEFAULT_RESULT, "description": "LLM returned empty response"}

    parsed = _parse_llm_json(raw_response)
    if parsed is None:
        logger.warning("Could not parse JSON from agent response: %s", raw_response[:200])
        return {**DEFAULT_RESULT, "description": raw_response[:500]}

    result = {**DEFAULT_RESULT}
    result["has_analysis"] = True

    for key in (
        "verdict", "fix_type", "remediation_fix", "dependency_type",
        "current_version", "fixed_version", "symbol_reachable",
        "go_vuln_id", "ghsa_id", "module", "description",
    ):
        if key in parsed and parsed[key] is not None:
            result[key] = parsed[key]

    valid_verdicts = {
        "NOT_VULNERABLE", "NOT_APPLICABLE", "NEEDS_REVIEW",
        "LOW", "MEDIUM", "HIGH", "CRITICAL", "AFFECTED",
    }
    if result["verdict"] not in valid_verdicts:
        result["verdict"] = "NEEDS_REVIEW"

    valid_fix_types = {
        "VERSION_BUMP", "TRIVIAL_BACKPORT", "NON_TRIVIAL_BACKPORT",
        "NOT_APPLICABLE", "NEEDS_REVIEW",
    }
    if result["fix_type"] not in valid_fix_types:
        result["fix_type"] = "NEEDS_REVIEW"

    result["risk_level"] = result["verdict"]
    result["fix_classification"] = result["fix_type"]

    return result
