"""Schemas for LLM extraction and structured output in Phase 3."""

from typing import List, Optional
from pydantic import BaseModel, Field

from risk_agent.models.schemas import ClaimType, ExtractedClaim, SeverityVerdict


class ExtractionClaimPayload(BaseModel):
    """Pydantic model representing an individual claim extracted by the LLM."""

    change_type: ClaimType = Field(
        ...,
        description="Type of change: BREAKING (removals, signature changes), DEPRECATION, NON_BREAKING (internal/unrelated), or INFO.",
    )
    affected_api: Optional[str] = Field(
        default=None,
        description="The exact identifier of the affected function, class, method, or attribute (e.g., 'transform_legacy', 'get', 'Client.connect').",
    )
    quoted_text: str = Field(
        ...,
        description="Exact verbatim excerpt from the release notes text supporting this claim (must be word-for-word, >= 6 tokens).",
    )
    description: str = Field(
        ...,
        description="Brief factual explanation of the change and its expected impact.",
    )
    llm_suggested_risk: SeverityVerdict = Field(
        default=SeverityVerdict.REVIEW,
        description="Suggested risk rating for this claim: NO_RISK_FOUND, REVIEW, or RISKY.",
    )


class ExtractionResponse(BaseModel):
    """Top-level structured output schema for the LLM extraction chain."""

    claims: List[ExtractionClaimPayload] = Field(
        default_factory=list,
        description="List of all breaking changes, deprecations, and API alterations identified in the release notes.",
    )
    summary: Optional[str] = Field(
        default=None,
        description="High-level factual summary of the version bump's impact.",
    )
    overall_risk: SeverityVerdict = Field(
        default=SeverityVerdict.REVIEW,
        description="Overall suggested risk verdict (NO_RISK_FOUND, REVIEW, or RISKY) based on the extracted claims.",
    )


class LLMExtractionResult(BaseModel):
    """Normalized output produced by LLMExtractor for the pipeline."""

    claims: List[ExtractedClaim] = Field(default_factory=list)
    overall_risk: SeverityVerdict = SeverityVerdict.REVIEW
    model_id: str
    prompt_version: str
    status: str = "success"  # "success" | "empty_notes" | "model_error"
    summary: Optional[str] = None
    error_message: Optional[str] = None

