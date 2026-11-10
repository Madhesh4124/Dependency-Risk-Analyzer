"""LLM-based extraction of breaking changes from release notes using Vertex AI & Google GenAI (Phase 3)."""

import json
import logging
import os
import random
import time
from typing import Any, List, Optional

from risk_agent.config import DEFAULT_CONFIG
from risk_agent.extraction.prompts import PROMPT_VERSION, SYSTEM_PROMPT, format_user_prompt
from risk_agent.extraction.schemas import (
    ExtractionResponse,
    LLMExtractionResult,
)
from risk_agent.models.schemas import ExtractedClaim, SeverityVerdict
from risk_agent.secrets import get_secret

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
        request_delay_seconds: Optional[float] = None,
    ):
        self.model_name = model_name or DEFAULT_CONFIG.vertex_ai_model
        self.project_id = project_id or DEFAULT_CONFIG.gcp_project_id
        self.location = (
            location
            or os.getenv("VERTEX_AI_LOCATION")
            or getattr(DEFAULT_CONFIG, "vertex_ai_location", "global")
            or "global"
        ).strip() or "global"
        self.temperature = temperature if temperature is not None else DEFAULT_CONFIG.llm_temperature
        self.prompt_version = prompt_version
        self.api_key = (
            api_key
            or get_secret("google-api-key", project_id=self.project_id)
            or os.getenv("GOOGLE_API_KEY")
            or os.getenv("GOOGLE_CLOUD_API_KEY")
            or os.getenv("GEMINI_API_KEY")
        )
        if request_delay_seconds is not None:
            self.request_delay_seconds = max(0.0, float(request_delay_seconds))
        else:
            env_delay = os.getenv("LLM_REQUEST_DELAY_MS")
            delay_ms = (
                int(env_delay.strip())
                if env_delay is not None and env_delay.strip().isdigit()
                else DEFAULT_CONFIG.llm_request_delay_ms
            )
            self.request_delay_seconds = max(0.0, delay_ms / 1000.0)
        self._custom_llm = llm
        self._genai_client = None
        self._langchain_llm = None

    def _invoke_genai_client(self, user_content: str) -> ExtractionResponse:
        """Invokes the official Google GenAI SDK with structured Pydantic output.

        Attempts API key first; if restricted (403 API_KEY_SERVICE_BLOCKED),
        automatically falls back to Vertex AI native IAM credentials.
        """
        from google import genai
        from google.genai import types

        def _call_client(use_vertex: bool, loc: Optional[str] = None) -> ExtractionResponse:
            kwargs = {}
            if not use_vertex and self.api_key:
                kwargs["api_key"] = self.api_key
            else:
                kwargs["vertexai"] = True
                if self.project_id:
                    kwargs["project"] = self.project_id
                target_loc = loc or self.location or "global"
                kwargs["location"] = target_loc

            client = genai.Client(**kwargs)
            config = types.GenerateContentConfig(
                system_instruction=SYSTEM_PROMPT,
                response_mime_type="application/json",
                response_schema=ExtractionResponse,
                temperature=self.temperature,
            )

            max_retries = 5
            response = None
            for attempt in range(max_retries):
                if attempt == 0 and self.request_delay_seconds > 0:
                    time.sleep(self.request_delay_seconds * random.uniform(0.85, 1.25))
                try:
                    response = client.models.generate_content(
                        model=self.model_name,
                        contents=user_content,
                        config=config,
                    )
                    break
                except Exception as exc:
                    exc_str = str(exc)
                    if (
                        "429" in exc_str
                        or "RESOURCE_EXHAUSTED" in exc_str
                        or "rate limit" in exc_str.lower()
                    ) and attempt < max_retries - 1:
                        backoff = (2 ** attempt) + random.uniform(1.0, 3.0)
                        logger.warning(
                            "LLMExtractor rate limited on Vertex AI (429 RESOURCE_EXHAUSTED). Retrying in %.2fs (attempt %d/%d)...",
                            backoff,
                            attempt + 1,
                            max_retries,
                        )
                        time.sleep(backoff)
                    else:
                        raise

            if hasattr(response, "parsed") and response.parsed:
                if isinstance(response.parsed, ExtractionResponse):
                    return response.parsed
                return ExtractionResponse.model_validate(response.parsed)

            return ExtractionResponse.model_validate_json(response.text)

        def _call_with_vertex_fallback() -> ExtractionResponse:
            try:
                return _call_client(use_vertex=True)
            except Exception as e:
                err_str = str(e)
                if ("404" in err_str or "NOT_FOUND" in err_str) and (self.location != "global"):
                    logger.warning(
                        "Vertex AI model %s not found in endpoint %s; automatically falling back to 'global': %s",
                        self.model_name,
                        self.location,
                        e,
                    )
                    return _call_client(use_vertex=True, loc="global")
                raise

        force_vertex = os.getenv("USE_VERTEX_AI", "").lower() in ("true", "1")
        if force_vertex:
            return _call_with_vertex_fallback()

        # 1. Try with API key if configured
        if self.api_key:
            try:
                return _call_client(use_vertex=False)
            except Exception as e:
                err_str = str(e)
                if "403" in err_str or "PERMISSION_DENIED" in err_str or "API_KEY_SERVICE_BLOCKED" in err_str:
                    logger.warning(
                        "API key blocked or restricted (%s); automatically falling back to Vertex AI native credentials",
                        e,
                    )
                    return _call_with_vertex_fallback()
                raise

        # 2. Otherwise use Vertex AI directly
        return _call_with_vertex_fallback()

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
            # 2. Otherwise use the official Google GenAI SDK (supports Vertex AI IAM ADC on 'global' and API key auth with 429 retry)
            else:
                response = self._invoke_genai_client(user_content)

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
