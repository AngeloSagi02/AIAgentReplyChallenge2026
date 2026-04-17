"""
agent.py - LLM-first fraud detection orchestrator for Deus Ex.

The agent uses a ReAct workflow where tools provide structured evidence and
triage hints, while the LLM makes final fraud decisions.
"""

from __future__ import annotations

import os
import re
import uuid
from typing import Any

try:
    import ulid
except ImportError:
    ulid = None
from dotenv import find_dotenv, load_dotenv
from langchain_core.messages import SystemMessage
from langchain_openai import ChatOpenAI
from langfuse import Langfuse, observe
from langfuse.langchain import CallbackHandler
from langgraph.prebuilt import create_react_agent

from tools import (
    get_all_tools,
    get_fallback_transaction_ids,
    get_flagged_transactions,
    ingest_candidate_transaction_ids,
)


load_dotenv(find_dotenv())


SYSTEM_PROMPT = SystemMessage(
    content="""You are The Eye, an elite fraud detection intelligence for MirrorPay in Reply Mirror.

MISSION
- Identify fraudulent TRANSACTIONS (not citizens).
- Balance 3 goals: detection quality, agentic speed, and economic cost.
- Prioritize high-financial-impact fraud while keeping false positives controlled.

MANDATORY WORKFLOW
1) Call list_citizens.
2) Call get_global_risk_overview to get triage candidates and priority citizens.
3) For top-risk citizens, call get_citizen_risk_summary and get_citizen_profile.
4) Inspect candidate IDs with get_transaction_details.
5) Use get_citizen_location_summary only when geo anomalies matter.
6) Use get_citizen_communications only for borderline/high-risk cases (expensive).
7) Conclude by calling mark_fraudulent_transactions with comma-separated transaction IDs.

SCORING STRATEGY
- Weight potential financial damage strongly (high amount, high velocity, account drain).
- Look for adaptive fraud patterns: new counterparties, unusual hours, geo mismatch,
  suspicious text, phishing context, and sudden behavior shifts.
- Avoid obvious legitimate patterns (regular salary inflows, recurring rent, low-risk routine spend).
- Do not under-flag strong evidence clusters: include all high-confidence IDs surfaced by tools,
  not just a tiny subset.

OUTPUT RULES
- Must submit a focused list of transaction UUIDs only.
- Never output an empty set.
- Never flag all transactions.
- Keep reasoning compact and tool-driven.
"""
)


MODELS = {
    "cheap": "meta-llama/llama-3.1-8b-instruct",
    "mid": "google/gemini-2.0-flash-001",
    "heavy": "anthropic/claude-haiku-4.5",
    "gemini-pro": "google/gemini-2.5-flash",
}


UUID_RE = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.IGNORECASE)


langfuse_client = Langfuse(
    public_key=os.getenv("LANGFUSE_PUBLIC_KEY"),
    secret_key=os.getenv("LANGFUSE_SECRET_KEY"),
    host=os.getenv("LANGFUSE_HOST", "https://challenges.reply.com/langfuse"),
)


def generate_session_id() -> str:
    """Generate Langfuse session ID in {TEAM_NAME}-{ULID} format.

    Falls back to UUID when ulid-py is not available in the active interpreter.
    """
    team = os.getenv("TEAM_NAME", "team").strip().replace(" ", "-")
    suffix = ulid.new().str if ulid is not None else uuid.uuid4().hex
    return f"{team}-{suffix}"


def resolve_model_id(model_arg: str) -> str:
    """Resolve model preset names or pass through explicit model IDs."""
    return MODELS.get(model_arg, model_arg)


def create_fraud_agent(model_id: str, temperature: float = 0.1):
    """Create the ReAct fraud detection agent with all tools registered."""
    model = ChatOpenAI(
        api_key=os.getenv("OPENROUTER_API_KEY"),
        base_url="https://openrouter.ai/api/v1",
        model=model_id,
        temperature=temperature,
        max_tokens=2200,
    )

    tools = get_all_tools()
    return create_react_agent(model, tools, prompt=SYSTEM_PROMPT)


def _extract_text_content(content: Any) -> str:
    if isinstance(content, str):
        return content

    if isinstance(content, list):
        chunks: list[str] = []
        for item in content:
            if isinstance(item, str):
                chunks.append(item)
                continue
            if isinstance(item, dict):
                text = item.get("text")
                if isinstance(text, str):
                    chunks.append(text)
        return "\n".join(chunks)

    return str(content)


def _extract_candidate_ids(text: str) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []

    for match in UUID_RE.findall(text or ""):
        tid = match.lower()
        if tid not in seen:
            seen.add(tid)
            ordered.append(tid)

    return ordered


@observe(name="deus_ex_fraud_run")
def run_agent(
    agent,
    session_id: str,
    dataset_name: str = "",
    verbose: bool = True,
) -> list[str]:
    """Run the agent end-to-end and return final flagged transaction IDs."""

    try:
        langfuse_client.update_current_span(
            metadata={
                "agent_type": "deus_ex_orchestrator",
                "dataset": dataset_name,
                "session_id": session_id,
            }
        )
    except Exception:
        # Tracing should never break inference if SDK behavior changes.
        pass

    langfuse_handler = CallbackHandler()

    primary_message = (
        f"Analyze the dataset '{dataset_name}' for fraudulent transactions.\n"
        "Use the required workflow in order, prioritize high-risk evidence, and then\n"
        "call mark_fraudulent_transactions with your final comma-separated UUID list.\n"
        "Begin now."
    )

    retry_message = (
        f"Retry finalization for '{dataset_name}'.\n"
        "Your previous output did not produce valid recorded transaction IDs.\n"
        "Re-check top risky candidates and call mark_fraudulent_transactions with a non-empty,\n"
        "focused set of valid UUIDs. Do not flag all transactions."
    )

    low_coverage_message = (
        f"Coverage recalibration for '{dataset_name}'.\n"
        "Your flagged set is likely too small for the risk profile returned by tools.\n"
        "Revisit global high-risk candidates and add every transaction with strong converging evidence\n"
        "(amount anomalies, burst behavior, suspicious text/phishing linkage, geo mismatch, balance shock).\n"
        "Call mark_fraudulent_transactions again with additional valid UUIDs."
    )

    config = {
        "callbacks": [langfuse_handler],
        "recursion_limit": 220,
        "metadata": {"langfuse_session_id": session_id},
    }

    transcript_chunks: list[str] = []

    def _stream_once(user_message: str) -> None:
        for event in agent.stream(
            {"messages": [("user", user_message)]},
            config=config,
            stream_mode="updates",
        ):
            for _, update in event.items():
                for msg in update.get("messages", []):
                    msg_type = getattr(msg, "type", "")

                    if msg_type == "tool":
                        if verbose:
                            tool_name = getattr(msg, "name", "unknown")
                            preview = _extract_text_content(getattr(msg, "content", ""))
                            preview = preview.replace("\n", " ")[:180]
                            print(f"  [Tool:{tool_name}] {preview}...")
                        continue

                    if hasattr(msg, "tool_calls") and msg.tool_calls:
                        if verbose:
                            for tc in msg.tool_calls:
                                name = tc.get("name", "unknown")
                                args_preview = str(tc.get("args", ""))[:140]
                                print(f"  [Call] {name}({args_preview})")
                        continue

                    text = _extract_text_content(getattr(msg, "content", ""))
                    if text.strip():
                        transcript_chunks.append(text)
                        if verbose:
                            preview = text.replace("\n", " ")[:220]
                            print(f"  [Agent] {preview}")

    if verbose:
        print("\n[Agent] Starting fraud investigation...")

    _stream_once(primary_message)
    flagged = get_flagged_transactions()

    # If the first pass is very conservative, run a targeted expansion pass.
    if 0 < len(flagged) < 42:
        if verbose:
            print(
                f"\n[Agent] Under-coverage detected ({len(flagged)} IDs). Triggering expansion pass..."
            )
        _stream_once(low_coverage_message)
        flagged = get_flagged_transactions()

    if not flagged:
        recovered = _extract_candidate_ids("\n".join(transcript_chunks))
        if recovered:
            added = ingest_candidate_transaction_ids(recovered)
            if verbose and added:
                print(f"[Agent] Recovered {added} valid IDs from model text output.")
        flagged = get_flagged_transactions()

    if not flagged:
        if verbose:
            print("\n[Agent] No valid IDs recorded. Triggering focused retry...")
        _stream_once(retry_message)
        flagged = get_flagged_transactions()

    if not flagged:
        recovered = _extract_candidate_ids("\n".join(transcript_chunks))
        if recovered:
            ingest_candidate_transaction_ids(recovered)
            flagged = get_flagged_transactions()

    if not flagged:
        fallback_ids = get_fallback_transaction_ids(max_ratio=0.10, min_count=14)
        ingest_candidate_transaction_ids(fallback_ids)
        flagged = get_flagged_transactions()
        if verbose:
            print(f"[Agent] Applied deterministic fallback with {len(fallback_ids)} IDs.")

    if verbose:
        print(f"\n[Agent] Investigation complete. Flagged {len(flagged)} transaction(s).")

    return flagged


def flush_langfuse() -> None:
    """Flush buffered traces to Langfuse backend."""
    try:
        langfuse_client.flush()
    except Exception:
        pass
