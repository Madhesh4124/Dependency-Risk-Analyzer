"""LLM-based extraction of breaking changes from release notes using Vertex AI (Phase 3)."""

import logging
from typing import Any, List, Optional

from langchain_core.messages import HumanMessage, SystemMessage

from risk_agent.config import DEFAULT_CONFIG
from risk_agent.extraction.prompts import PROMPT_VERSION, SYSTEM_PROMPT, format_user_prompt
from risk_agent.extraction.schemas import (
    ExtractionResponse,
    LLMExtractionResult,
)
from risk_agent.models.schemas import ExtractedClaim, SeverityVerdict

logger = logging.getLogger(__name__)


class LLMExtractor:
    """Extracts structured breaking change claims from release notes using Vertex AI Gemini models."""

    def __init__(
        self,
        model_name: Optional[str] = None,
        project_id: Optional[str] = None,
        location: Optional[str] = None,
        temperature: Optional[float] = None,
        prompt_version: str = PROMPT_VERSION,
        llm: Optional[Any] = None,
    ):
        self.model_name = model_name or DEFAULT_CONFIG.vertex_ai_model
        self.project_id = project_id or DEFAULT_CONFIG.gcp_project_id
        self.location = location or DEFAULT_CONFIG.gcp_region
        self.temperature = temperature if temperature is not None else DEFAULT_CONFIG.llm_temperature
        self.prompt_version = prompt_version
        self._custom_llm = llm
        self._llm_instance = None

    def _get_llm(self) -> Any:
        """Returns the configured LLM, lazily initializing ChatVertexAI if not provided."""
        if self._custom_llm is not None:
            return self._custom_llm

        if self._llm_instance is None:
            try:
                from langchain_google_vertexai import ChatVertexAI

                kwargs = {
                    "model_name": self.model_name,
                    "location": self.location,
                    "temperature": self.temperature,
                }
                if self.project_id:
                    kwargs["project"] = self.project_id

                self._llm_instance = ChatVertexAI(**kwargs)
            except Exception as e:
                logger.error(f"Failed to initialize ChatVertexAI for model {self.model_name}: {e}")
                raise

        return self._llm_instance

    def extract_claims(
        self,
        package_name: str,
        old_version: str,
        new_version: str,
        release_notes: str,
    ) -> LLMExtractionResult:
        """Extracts candidate breaking changes and deprecations with verbatim quotes from release notes."""
        if not release_notes or not release_notes.strip():
            logger.info(f"Release notes for {package_name} are empty or missing. Returning empty claims.")
            return LLMExtractionResult(
                claims=[],
                overall_risk=SeverityVerdict.REVIEW,
                model_id=self.model_name,
                prompt_version=self.prompt_version,
                status="empty_notes",
                summary="Release notes were empty or unavailable.",
            )

        user_content = format_user_prompt(
            package_name=package_name,
            old_version=old_version,
            new_version=new_version,
            release_notes=release_notes,
        )

        messages = [
            SystemMessage(content=SYSTEM_PROMPT),
            HumanMessage(content=user_content),
        ]

        try:
            llm = self._get_llm()
            structured_chain = llm.with_structured_output(ExtractionResponse)
            response: ExtractionResponse = structured_chain.invoke(messages)

            extracted_claims: List[ExtractedClaim] = []
            for i, p in enumerate(response.claims, start=1):
                claim = ExtractedClaim(
                    claim_id=f"claim-{i}",
                    claim_type=p.change_type,
                    affected_api=p.affected_api.strip() if p.affected_api else None,
                    quoted_text=p.quoted_text.strip(),
                    description=p.description.strip(),
                    model_id=self.model_name,
                    prompt_version=self.prompt_version,
                )
                extracted_claims.append(claim)

            return LLMExtractionResult(
                claims=extracted_claims,
                overall_risk=response.overall_risk,
                model_id=self.model_name,
                prompt_version=self.prompt_version,
                status="success",
                summary=response.summary,
            )

        except Exception as e:
            logger.error(
                f"LLM extraction failed for {package_name} ({old_version} -> {new_version}): {e}",
                exc_info=True,
            )
            # Architectural invariant: model failure must NOT crash the pipeline.
            # Return empty claims and fall back to REVIEW.
            return LLMExtractionResult(
                claims=[],
                overall_risk=SeverityVerdict.REVIEW,
                model_id=self.model_name,
                prompt_version=self.prompt_version,
                status="model_error",
                error_message=str(e),
                summary="LLM extraction encountered an error; falling back to deterministic floor.",
            )

