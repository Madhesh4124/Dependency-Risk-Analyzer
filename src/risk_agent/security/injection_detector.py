"""Adversarial and prompt injection detection engine for Phase 6.

Provides multi-layered defense:
1. Google Cloud Model Armor / Vertex AI Safety API integration (when enabled/available).
2. Resilient local heuristics, regex pattern matching, and normalization fallback.
3. Strict sanitization to prevent secondary markdown/XSS injection in PR comments.
"""

from dataclasses import dataclass
from enum import Enum
import html
import re
from typing import Optional, Sequence
import logging

logger = logging.getLogger(__name__)


class InjectionPatternType(str, Enum):
    INSTRUCTION_RESET = "INSTRUCTION_RESET"
    SECRET_EXFILTRATION = "SECRET_EXFILTRATION"
    FORCED_VERDICT_OVERRIDE = "FORCED_VERDICT_OVERRIDE"
    ROLEPLAY_JAILBREAK = "ROLEPLAY_JAILBREAK"
    MODEL_ARMOR_FLAGGED = "MODEL_ARMOR_FLAGGED"


@dataclass
class InjectionResult:
    detected: bool = False
    pattern_type: Optional[InjectionPatternType] = None
    matched_snippet: Optional[str] = None
    sanitized_snippet: Optional[str] = None
    confidence: float = 0.0
    engine: str = "none"  # "local_heuristic" | "model_armor" | "none"


def sanitize_snippet(raw_snippet: str, max_length: int = 100) -> str:
    """Sanitizes an untrusted injection snippet for safe rendering in GitHub PR markdown.

    Escapes HTML entities, strips markdown formatting characters (backticks, brackets, asterisks),
    and truncates to prevent secondary UI disruption.
    """
    if not raw_snippet:
        return ""

    # Replace newlines and excessive whitespace with a single space
    cleaned = re.sub(r"\s+", " ", raw_snippet.strip())
    # Defang backticks, brackets, html tags
    cleaned = cleaned.replace("`", "'").replace("<", "&lt;").replace(">", "&gt;")
    cleaned = cleaned.replace("[", "(").replace("]", ")")

    if len(cleaned) > max_length:
        cleaned = cleaned[: max_length - 3] + "..."

    return cleaned


# Compiled Regex Rules for Local Heuristic Tripwire
_PATTERNS = {
    InjectionPatternType.INSTRUCTION_RESET: [
        re.compile(r"\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions?|directives?|rules?)\b", re.IGNORECASE),
        re.compile(r"\b(?:system\s+(?:prompt\s+)?override|new\s+system\s+directive|developer\s+mode)\b", re.IGNORECASE),
        re.compile(r"\b(?:disregard\s+system\s+prompt|reset\s+instructions?)\b", re.IGNORECASE),
    ],
    InjectionPatternType.FORCED_VERDICT_OVERRIDE: [
        re.compile(r"\b(?:output|return|set|mark|rate|label)\s+(?:(?:this|it)\s+)?(?:as\s+|to\s+|verdict\s+as\s+)?(?:['\"]?)(?:NO_RISK_FOUND|REVIEW|SAFE)(?:['\"]?)\b", re.IGNORECASE),
        re.compile(r"\bverdict\s*[:=]\s*['\"]?(?:NO_RISK_FOUND|SAFE)['\"]?\b", re.IGNORECASE),
        re.compile(r"\bdo\s+not\s+(?:flag|report|raise)\s+(?:any\s+)?(?:risk|breaking\s+changes?)\b", re.IGNORECASE),
    ],
    InjectionPatternType.SECRET_EXFILTRATION: [
        re.compile(r"\b(?:print|dump|output|leak|reveal|echo)\s+(?:all\s+)?(?:env|environment|secrets?|credentials?|tokens?|api[_\s]?keys?)\b", re.IGNORECASE),
        re.compile(r"\b(?:send|post|exfiltrate)\s+(?:to|secrets?|tokens?)\b", re.IGNORECASE),
        re.compile(r"\$\{?(?:GITHUB_TOKEN|GCP_SECRET|VERTEX_API_KEY)\}?", re.IGNORECASE),
    ],
    InjectionPatternType.ROLEPLAY_JAILBREAK: [
        re.compile(r"\b(?:you\s+are\s+now\s+in\s+unrestricted\s+mode|dan\s+mode|always\s+say\s+yes)\b", re.IGNORECASE),
        re.compile(r"\b(?:act\s+as|pretend\s+you\s+are)\s+(?:an?\s+unrestricted|a\s+hacked)\s+(?:assistant|ai)\b", re.IGNORECASE),
    ],
}


class InjectionDetector:
    """Scans untrusted pull request data and changelogs for prompt injection and adversarial attacks."""

    def __init__(self, enable_model_armor: bool = False, model_armor_template: Optional[str] = None):
        self.enable_model_armor = enable_model_armor
        self.model_armor_template = model_armor_template

    def _normalize_text(self, text: str) -> str:
        """Normalizes input text by removing zero-width characters and decoding entities."""
        if not text:
            return ""

        # Unescape HTML entities
        unescaped = html.unescape(text)

        # Remove zero-width spaces and soft hyphens used for evasion
        cleaned = re.sub(r"[\u200B-\u200D\uFEFF\u00AD]", "", unescaped)

        return cleaned

    def scan_text(self, text: str) -> InjectionResult:
        """Scans a single text input for injection patterns using Model Armor and local heuristics."""
        if not text or not text.strip():
            return InjectionResult(detected=False)

        normalized = self._normalize_text(text)

        # 1. Try Google Cloud Model Armor if explicitly configured
        if self.enable_model_armor and self.model_armor_template:
            result = self._scan_with_model_armor(normalized)
            if result.detected:
                return result

        # 2. Local Heuristic Engine (fast, CPU-bound, robust fallback)
        return self._scan_local_heuristics(normalized)

    def _scan_local_heuristics(self, text: str) -> InjectionResult:
        """Evaluates normalized text against categorized heuristic regexes."""
        for pattern_type, regex_list in _PATTERNS.items():
            for regex in regex_list:
                match = regex.search(text)
                if match:
                    raw_snippet = match.group(0)
                    sanitized = sanitize_snippet(raw_snippet)
                    logger.warning(
                        "Adversarial prompt injection pattern detected: %s (snippet: '%s')",
                        pattern_type.value,
                        sanitized,
                    )
                    return InjectionResult(
                        detected=True,
                        pattern_type=pattern_type,
                        matched_snippet=raw_snippet,
                        sanitized_snippet=sanitized,
                        confidence=0.95,
                        engine="local_heuristic",
                    )

        return InjectionResult(detected=False, engine="local_heuristic")

    def _scan_with_model_armor(self, text: str) -> InjectionResult:
        """Invokes Google Cloud Model Armor Client to check for adversarial content."""
        try:
            from google.cloud import modelarmor_v1  # type: ignore

            client = modelarmor_v1.ModelArmorClient()
            request = modelarmor_v1.SanitizeUserPromptRequest(
                name=self.model_armor_template,
                user_prompt_data={"text": text},
            )
            response = client.sanitize_user_prompt(request=request)

            # Check if any filter was triggered
            if (
                hasattr(response, "sanitization_result")
                and response.sanitization_result.filter_match_state.name == "MATCH_FOUND"
            ):
                snippet = text[:80]
                return InjectionResult(
                    detected=True,
                    pattern_type=InjectionPatternType.MODEL_ARMOR_FLAGGED,
                    matched_snippet=snippet,
                    sanitized_snippet=sanitize_snippet(snippet),
                    confidence=0.99,
                    engine="model_armor",
                )
        except Exception as e:
            logger.info("Model Armor inspection skipped or failed (%s); using local heuristic engine", e)

        return InjectionResult(detected=False, engine="model_armor")

    def scan_pr(
        self,
        pr_title: str = "",
        pr_body: str = "",
        release_notes: str = "",
        commit_messages: Optional[Sequence[str]] = None,
    ) -> InjectionResult:
        """Comprehensive scan across all untrusted entry points of a pull request."""
        # 1. Scan PR title
        title_res = self.scan_text(pr_title)
        if title_res.detected:
            return title_res

        # 2. Scan PR body / description
        body_res = self.scan_text(pr_body)
        if body_res.detected:
            return body_res

        # 3. Scan commit messages
        if commit_messages:
            for msg in commit_messages:
                commit_res = self.scan_text(msg)
                if commit_res.detected:
                    return commit_res

        # 4. Scan release notes
        notes_res = self.scan_text(release_notes)
        if notes_res.detected:
            return notes_res

        return InjectionResult(detected=False)
