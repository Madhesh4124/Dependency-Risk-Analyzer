"""LLM-based extraction of breaking changes from release notes using Vertex AI & Google GenAI (Phase 3)."""

import json
import logging
import os
from typing import Any, List, Optional

from risk_agent.config import DEFAULT_CONFIG
from risk_agent.extraction.prompts import PROMPT_VERSION, SYSTEM_PROMPT, format_user_prompt
from risk_agent.extraction.schemas import (
    ExtractionResponse,
    LLMExtractionResult,
)
from risk_agent.models.schemas import ExtractedClaim, SeverityVerdict

logger = logging.getLogger(__name__)


class LLMExtractor:
    """Extracts structured breaking change claims from release notes using Gemini models on Google Cloud."""

    def __init__(
        self,
        model_name: Optional[str] = None,
        project_id: Optional[str] = None,
        location: Optional[str] = None,
        temperature: Optional[float] = None,
        prompt_version: str = PROMPT_VERSION,
        api_key: Optional[str] = None,
        llm: Optional[Any] = None,
    ):
        self.model_name = model_name or DEFAULT_CONFIG.vertex_ai_model
        self.project_id = project_id or DEFAULT_CONFIG.gcp_project_id
        self.location = location or DEFAULT_CONFIG.gcp_region
        self.temperature = temperature if temperature is not None else DEFAULT_CONFIG.llm_temperature
        self.prompt_version = prompt_version
        self.api_key = api_key or os.getenv("GOOGLE_CLOUD_API_KEY") or os.getenv("GEMINI_API_KEY")
        self._custom_llm = llm
        self._genai_client = None
        self._langchain_llm = None

    def _invoke_genai_client(self, user_content: str) -> ExtractionResponse:
        """Invokes the official Google GenAI SDK with structured Pydantic output."""
        from google import genai
        from google.genai import types

        client_kwargs = {
            "vertexai": True,
            "api_key": self.api_key,
        }
        if self.project_id:
            client_kwargs["project"] = self.project_id
        if self.location:
            client_kwargs["location"] = self.location

        client = genai.Client(**client_kwargs)

        config = types.GenerateContentConfig(
            system_instruction=SYSTEM_PROMPT,
            response_mime_type="application/json",
            response_schema=ExtractionResponse,
            temperature=self.temperature,
        )

        response = client.models.generate_content(
            model=self.model_name,
            contents=user_content,
            config=config,
        )

        if hasattr(response, "parsed") and response.parsed:
            if isinstance(response.parsed, ExtractionResponse):
                return response.parsed
            return ExtractionResponse.model_validate(response.parsed)

        return ExtractionResponse.model_validate_json(response.text)

    def _invoke_custom_or_langchain_llm(self, user_content: str) -> ExtractionResponse:
        """Invokes a custom or LangChain LLM using RunnableSequence + with_structured_output."""
        from langchain_core.messages import HumanMessage, SystemMessage

        if self._custom_llm is not None:
            llm = self._custom_llm
        else:
            from langchain_google_vertexai import ChatVertexAI

            kwargs = {
                "model_name": self.model_name,
                "location": self.location,
                "temperature": self.temperature,
            }
            if self.project_id:
                kwargs["project"] = self.project_id
            llm = ChatVertexAI(**kwargs)

        messages = [
            SystemMessage(content=SYSTEM_PROMPT),
            HumanMessage(content=user_content),
        ]

        structured_chain = llm.with_structured_output(ExtractionResponse)
        return structured_chain.invoke(messages)

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

        try:
            # 1. If an explicit custom LLM or mock is injected (e.g. unit tests), use it
            if self._custom_llm is not None:
                response = self._invoke_custom_or_langchain_llm(user_content)
            # 2. If a Google Cloud API key (account-bound auth key) is present, use official Google GenAI
            elif self.api_key:
                response = self._invoke_genai_client(user_content)
            # 3. Otherwise fall back to ChatVertexAI with default ADC
            else:
                response = self._invoke_custom_or_langchain_llm(user_content)

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
            return LLMExtractionResult(
                claims=[],
                overall_risk=SeverityVerdict.REVIEW,
                model_id=self.model_name,
                prompt_version=self.prompt_version,
                status="model_error",
                error_message=str(e),
                summary="LLM extraction encountered an error; falling back to deterministic floor.",
            )
