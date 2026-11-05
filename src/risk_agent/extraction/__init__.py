"""Extraction module for Phase 3 LLM-assisted analysis."""

from risk_agent.extraction.extractor import LLMExtractor
from risk_agent.extraction.prompts import PROMPT_VERSION, SYSTEM_PROMPT, format_user_prompt
from risk_agent.extraction.schemas import (
    ExtractionClaimPayload,
    ExtractionResponse,
    LLMExtractionResult,
)

__all__ = [
    "LLMExtractor",
    "ExtractionClaimPayload",
    "ExtractionResponse",
    "LLMExtractionResult",
    "PROMPT_VERSION",
    "SYSTEM_PROMPT",
    "format_user_prompt",
]

