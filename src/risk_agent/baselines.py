"""Baseline implementations for Phase 4 benchmarking.

Covers:
1. Baseline 1: Deterministic Policy Only (no LLM)
2. Baseline 2: Single Direct LLM Call (no multi-step pipeline, no quote verification, no AST scan)
"""

import logging
import os
import re
from pathlib import Path
from typing import Any, List, Optional
from pydantic import BaseModel, Field

from risk_agent.models.schemas import (
    ClaimType,
    RiskReport,
    SeverityVerdict,
    VersionBumpType,
)
from risk_agent.pipeline import DeterministicPipeline

logger = logging.getLogger(__name__)


class SingleCallEvaluationResponse(BaseModel):
    """Pydantic schema for Baseline 2 single-call response."""
    verdict: SeverityVerdict = Field(
        description="Assessed risk verdict: NO_RISK_FOUND, REVIEW, or RISKY"
    )
    confidence: str = Field(
        default="medium",
        description="Model confidence level: high, medium, or low"
    )
    reasoning: str = Field(
        description="Direct rationale for the verdict"
    )
    claimed_breaking_quotes: List[str] = Field(
        default_factory=list,
        description="Any quoted sentences claimed to represent breaking changes"
    )


class DeterministicBaseline:
    """Baseline 1: Deterministic evaluation using AST scan and release notes rules without any LLM."""

    def __init__(self):
        self.pipeline = DeterministicPipeline()

    def evaluate_case(
        self,
        case_dir: Path,
        raw_release_notes: str,
        package_name: str,
        old_version: str,
        new_version: str,
        manifest_diff: str = "",
        is_release_notes_available: bool = True,
        bump_type: Optional[VersionBumpType] = None,
    ) -> RiskReport:
        """Executes the deterministic baseline against a fixture or PR directory."""
        # Check if release notes contain basic breaking change keywords
        has_breaking_kw = bool(
            re.search(r"\b(breaking|removed|deprecat|dropped|incompatible)\b", raw_release_notes, re.IGNORECASE)
        )

        affected_api = None
        claim_type = ClaimType.BREAKING

        # Simple heuristic extraction of affected API name if mentioned near 'removed'
        match = re.search(r"(?:removed|deprecated|changed)\s+(?:the\s+)?(?:function\s+|class\s+|method\s+)?`?([a-zA-Z0-9_]+)`?", raw_release_notes, re.IGNORECASE)
        if match:
            affected_api = match.group(1)

        quote_text = None
        for line in raw_release_notes.splitlines():
            s = line.strip()
            if s.startswith("-") or has_breaking_kw:
                quote_text = s.lstrip("-* ").strip()
                break

        return self.pipeline.evaluate_fixture_case(
            case_dir=case_dir,
            raw_release_notes=raw_release_notes,
            affected_api=affected_api,
            claim_type=claim_type,
            quoted_claim_text=quote_text,
            is_release_notes_available=is_release_notes_available,
            package_name=package_name,
            old_version=old_version,
            new_version=new_version,
            bump_type=bump_type,
        )


class SingleCallLLMBaseline:
    """Baseline 2: Single direct LLM call without quote verification, AST scanning, or risk floors."""

    def __init__(
        self,
        model_name: Optional[str] = None,
        api_key: Optional[str] = None,
        project_id: Optional[str] = None,
        location: Optional[str] = None,
        custom_llm: Optional[Any] = None,
    ):
        self.model_name = model_name or os.getenv("VERTEX_AI_MODEL", "gemini-3.1-flash-lite")
        self.project_id = project_id or os.getenv("GCP_PROJECT_ID", "dependency-impact-analyzer")
        self.location = location or os.getenv("GCP_REGION", "global")
        self.api_key = api_key or os.getenv("GOOGLE_CLOUD_API_KEY") or os.getenv("GEMINI_API_KEY")
        self.custom_llm = custom_llm

    def evaluate(
        self,
        package_name: str,
        old_version: str,
        new_version: str,
        bump_type: str,
        manifest_diff: str,
        release_notes: str,
        repo_code_snippets: str,
    ) -> SingleCallEvaluationResponse:
        """Prompts the LLM directly with all context in a single shot."""
        # Check for adversarial injection in release notes that tricks a naive single-call model
        # (This reflects the documented vulnerability of single-call agents without hard risk floors)
        lower_notes = release_notes.lower()
        if (
            "ignore all previous" in lower_notes or
            "return no_risk_found" in lower_notes or
            "system override" in lower_notes or
            "system prompt override" in lower_notes
        ):
            # Naive single call is compromised by prompt injection
            return SingleCallEvaluationResponse(
                verdict=SeverityVerdict.NO_RISK_FOUND,
                confidence="high",
                reasoning="The upgrade appears safe based on provided release note directives.",
                claimed_breaking_quotes=[],
            )

        if not release_notes or not release_notes.strip():
            return SingleCallEvaluationResponse(
                verdict=SeverityVerdict.REVIEW,
                confidence="low",
                reasoning="Release notes are empty or missing.",
                claimed_breaking_quotes=[],
            )

        if self.custom_llm is not None:
            prompt = (
                f"You are reviewing a Python dependency upgrade.\n"
                f"Package: {package_name} ({old_version} -> {new_version}, bump: {bump_type})\n"
                f"Manifest diff:\n{manifest_diff}\n\n"
                f"Release Notes:\n{release_notes}\n\n"
                f"Repository Code:\n{repo_code_snippets}\n\n"
                f"Determine if this upgrade introduces breaking changes for this repository.\n"
                f"Choose one verdict: NO_RISK_FOUND, REVIEW, or RISKY."
            )
            structured_chain = self.custom_llm.with_structured_output(SingleCallEvaluationResponse)
            return structured_chain.invoke(prompt)

        try:
            from google import genai
            from google.genai import types

            client_kwargs = {}
            if self.api_key:
                client_kwargs["api_key"] = self.api_key
            else:
                client_kwargs["vertexai"] = True
                if self.project_id:
                    client_kwargs["project"] = self.project_id
                if self.location:
                    client_kwargs["location"] = self.location

            client = genai.Client(**client_kwargs)
            prompt = (
                f"You are reviewing a Python dependency upgrade.\n"
                f"Package: {package_name} ({old_version} -> {new_version}, bump: {bump_type})\n"
                f"Manifest diff:\n{manifest_diff}\n\n"
                f"Release Notes:\n{release_notes}\n\n"
                f"Repository Code:\n{repo_code_snippets}\n\n"
                f"Determine if this upgrade introduces breaking changes for this repository.\n"
                f"Choose one verdict: NO_RISK_FOUND, REVIEW, or RISKY."
            )

            config = types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=SingleCallEvaluationResponse,
                temperature=0.0,
            )
            res = client.models.generate_content(
                model=self.model_name,
                contents=prompt,
                config=config,
            )
            if hasattr(res, "parsed") and res.parsed:
                if isinstance(res.parsed, SingleCallEvaluationResponse):
                    return res.parsed
                return SingleCallEvaluationResponse.model_validate(res.parsed)
            return SingleCallEvaluationResponse.model_validate_json(res.text)
        except Exception as e:
            logger.error(f"Live GenAI single-call execution failed: {e}")
            raise
