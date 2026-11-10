"""Adversarial and prompt injection detection engine for Phase 6.

Provides Google Cloud Model Armor as the primary ingress/egress security engine,
reinforced by defense-in-depth local normalization and deterministic quarantine:
1. Google Cloud Model Armor regional API (`sanitize_user_prompt` & `sanitize_model_response`)
   with multi-language detection, chunked scanning, decoded-payload inspection,
   all 6 filter families (PI/Jailbreak, Malicious URI, SDP inspect/deidentify/redact,
   RAI, CSAM, Virus Scan), and fail-closed status tracking.
2. Defense-in-depth local heuristics, delimiter-escape rules, decoded Base64/URL
   inspection, and Unicode/NFKC + bidi/zero-width normalization.
3. Quarantine & strict snippet sanitization to isolate untrusted text before LLM extraction
   and prevent secondary markdown/XSS injection in PR comments.
"""

import base64
from dataclasses import dataclass, field
from enum import Enum
import html
import logging
import os
import re
from typing import Any, List, Optional, Sequence, Tuple
import unicodedata
from urllib.parse import unquote

from risk_agent.config import DEFAULT_CONFIG

logger = logging.getLogger(__name__)

_TEMPLATE_RESOURCE_RE = re.compile(r"^projects/([^/]+)/locations/([^/]+)/templates/([^/]+)$")
_HTML_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)
_BASE64_CANDIDATE_RE = re.compile(r"\b[A-Za-z0-9+/]{24,}={0,2}\b")


class InjectionPatternType(str, Enum):
    INSTRUCTION_RESET = "INSTRUCTION_RESET"
    SECRET_EXFILTRATION = "SECRET_EXFILTRATION"
    FORCED_VERDICT_OVERRIDE = "FORCED_VERDICT_OVERRIDE"
    ROLEPLAY_JAILBREAK = "ROLEPLAY_JAILBREAK"
    DELIMITER_ESCAPE = "DELIMITER_ESCAPE"
    ENCODING_OBFUSCATION = "ENCODING_OBFUSCATION"
    MALICIOUS_URI = "MALICIOUS_URI"
    SENSITIVE_DATA_LEAK = "SENSITIVE_DATA_LEAK"
    MODEL_ARMOR_FLAGGED = "MODEL_ARMOR_FLAGGED"


@dataclass
class InjectionResult:
    detected: bool = False
    pattern_type: Optional[InjectionPatternType] = None
    matched_snippet: Optional[str] = None
    sanitized_snippet: Optional[str] = None
    confidence: float = 0.0
    engine: str = "none"  # "model_armor" | "local_heuristic" | "model_armor+local_heuristic" | "none"
    triggered_filters: List[str] = field(default_factory=list)
    model_armor_status: str = "disabled"  # "matched" | "clean" | "error" | "disabled"
    model_armor_error: Optional[str] = None
    surfaces_flagged: List[str] = field(default_factory=list)
    matched_uris: List[str] = field(default_factory=list)
    sdp_info_types: List[str] = field(default_factory=list)
    deidentified_text: Optional[str] = None
    deidentified_release_notes: Optional[str] = None


def sanitize_snippet(raw_snippet: str, max_length: int = 100) -> str:
    """Sanitizes an untrusted injection snippet for safe rendering in GitHub PR markdown.

    Escapes HTML entities, strips markdown formatting characters (backticks, brackets),
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


def resolve_model_armor_config(
    project_id: Optional[str] = None,
    location: Optional[str] = None,
    template_id: Optional[str] = None,
    model_armor_template: Optional[str] = None,
) -> Tuple[Optional[str], str]:
    """Resolves the canonical Model Armor template path and regional endpoint location.

    Returns:
        Tuple[Optional[str], str]: (full_template_resource_name, location)
    """
    eff_project = (
        project_id
        or os.getenv("GCP_PROJECT_ID")
        or os.getenv("GOOGLE_CLOUD_PROJECT")
        or DEFAULT_CONFIG.gcp_project_id
        or "dependency-impact-analyzer"
    )
    eff_location = (
        location
        or os.getenv("MODEL_ARMOR_LOCATION")
        or os.getenv("GCP_REGION")
        or os.getenv("GOOGLE_CLOUD_REGION")
        or DEFAULT_CONFIG.model_armor_location
        or "asia-south1"
    )
    raw_template = (
        model_armor_template
        if model_armor_template is not None
        else (os.getenv("MODEL_ARMOR_TEMPLATE") or DEFAULT_CONFIG.model_armor_template)
    )
    env_tpl_id = os.getenv("MODEL_ARMOR_TEMPLATE_ID")
    raw_template_id = (
        template_id
        if template_id is not None
        else (env_tpl_id if env_tpl_id is not None else DEFAULT_CONFIG.model_armor_template_id)
    )

    if raw_template:
        match = _TEMPLATE_RESOURCE_RE.match(raw_template.strip())
        if match:
            return raw_template.strip(), match.group(2)
        if "/" not in raw_template.strip():
            # Treat short name passed via MODEL_ARMOR_TEMPLATE as template ID
            raw_template_id = raw_template.strip()
        else:
            return raw_template.strip(), eff_location

    if raw_template_id:
        clean_id = raw_template_id.strip()
        if clean_id:
            return f"projects/{eff_project}/locations/{eff_location}/templates/{clean_id}", eff_location

    return None, eff_location


# Compiled Regex Rules for Defense-in-Depth Local Heuristic Tripwire
_PATTERNS = {
    InjectionPatternType.INSTRUCTION_RESET: [
        re.compile(r"\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions?|directives?|rules?)\b", re.IGNORECASE),
        re.compile(r"\bforget\s+everything\s+(?:above|prior|previously)\b", re.IGNORECASE),
        re.compile(r"\b(?:system\s+(?:prompt\s+|instructions?\s+)?override|new\s+system\s+(?:directive|prompt)|developer\s+mode)\b", re.IGNORECASE),
        re.compile(r"\b(?:disregard\s+system\s+prompt|reset\s+instructions?|override\s+safety\s+rules?)\b", re.IGNORECASE),
    ],
    InjectionPatternType.FORCED_VERDICT_OVERRIDE: [
        re.compile(r"\b(?:output|return|set|mark|rate|label|classify)\s+(?:(?:this|it)\s+)?(?:as\s+|to\s+|verdict\s+as\s+)?(?:['\"]?)(?:NO_RISK_FOUND|SAFE)(?:['\"]?)\b", re.IGNORECASE),
        re.compile(r"\b(?:output|return|set|mark|rate|label)\s+(?:(?:this|it)\s+)?(?:as\s+|to\s+|verdict\s+as\s+)?(?:['\"]?)REVIEW(?:['\"]?)\b", re.IGNORECASE),
        re.compile(r"\bverdict\s*[:=]\s*['\"]?(?:NO_RISK_FOUND|SAFE)['\"]?\b", re.IGNORECASE),
        re.compile(r'"overall_risk"\s*:\s*"NO_RISK_FOUND"', re.IGNORECASE),
        re.compile(r"\bdo\s+not\s+(?:flag|report|raise)\s+(?:any\s+)?(?:risks?|breaking\s+changes?|alerts?)\b", re.IGNORECASE),
    ],
    InjectionPatternType.SECRET_EXFILTRATION: [
        re.compile(r"\b(?:print|dump|output|leak|reveal|echo|exfiltrate)\s+(?:all\s+)?(?:env|environment|secrets?|credentials?|tokens?|api[_\s]?keys?|private[_\s]?keys?)\b", re.IGNORECASE),
        re.compile(r"\b(?:send|post|exfiltrate|upload)\s+(?:to|secrets?|tokens?|credentials?|env)\b", re.IGNORECASE),
        re.compile(r"\$\{?(?:GITHUB_TOKEN|GITHUB_APP_PRIVATE_KEY|GCP_SECRET|VERTEX_API_KEY|GOOGLE_API_KEY|AWS_SECRET_ACCESS_KEY)\}?", re.IGNORECASE),
    ],
    InjectionPatternType.ROLEPLAY_JAILBREAK: [
        re.compile(r"\b(?:you\s+are\s+now\s+in\s+unrestricted\s+mode|dan\s+mode|always\s+say\s+yes|bypass\s+(?:safety|policy)\s+(?:rules?|checks?|filters?))\b", re.IGNORECASE),
        re.compile(r"\b(?:act\s+as|pretend\s+you\s+are)\s+(?:an?\s+unrestricted|a\s+hacked|an\s+unfiltered)\s+(?:assistant|ai|reviewer)\b", re.IGNORECASE),
    ],
    InjectionPatternType.DELIMITER_ESCAPE: [
        re.compile(r"</\s*RELEASE_NOTES_DATA\s*>", re.IGNORECASE),
        re.compile(r"<\s*RELEASE_NOTES_DATA\s*>", re.IGNORECASE),
        re.compile(r"</?\s*(?:SYSTEM_PROMPT|SYSTEM_INSTRUCTIONS?|USER_PROMPT)\s*>", re.IGNORECASE),
        re.compile(r"(?:<\|im_start\|>|<\|im_end\|>|<\|endoftext\|>|\[/?INST\])", re.IGNORECASE),
    ],
}

# Patterns specifically monitored inside LLM model responses (egress guard)
_MODEL_RESPONSE_EXFIL_PATTERNS = [
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"\bgh[ps]_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z\-_]{30,}\b"),
    re.compile(r"\b(?:GITHUB_TOKEN|GCP_SECRET|AWS_SECRET_ACCESS_KEY)\s*=\s*['\"]?[A-Za-z0-9/+=_-]{8,}"),
]


def _enum_name(val: Any) -> str:
    if val is None:
        return ""
    name = getattr(val, "name", None)
    if name:
        return str(name).upper()
    return str(val).upper()


def _match_state_is_found(state: Any) -> bool:
    """Safely determines whether a Model Armor FilterMatchState represents MATCH_FOUND."""
    if state is None:
        return False
    name = getattr(state, "name", None)
    if name:
        return name == "MATCH_FOUND"
    if isinstance(state, int):
        return state == 2
    return str(state).upper().endswith("MATCH_FOUND")


class InjectionDetector:
    """Primary Model Armor + defense-in-depth security scanner for PR inputs and LLM responses."""

    def __init__(
        self,
        enable_model_armor: Optional[bool] = None,
        model_armor_template: Optional[str] = None,
        project_id: Optional[str] = None,
        location: Optional[str] = None,
        template_id: Optional[str] = None,
        model_armor_client: Optional[Any] = None,
        max_chunk_chars: Optional[int] = None,
        chunk_overlap: Optional[int] = None,
        fail_closed: Optional[bool] = None,
        scan_model_response_enabled: Optional[bool] = None,
        enable_multilang: Optional[bool] = None,
    ):
        resolved_template, resolved_location = resolve_model_armor_config(
            project_id=project_id,
            location=location,
            template_id=template_id,
            model_armor_template=model_armor_template,
        )
        if enable_model_armor is None:
            env_flag = os.getenv("ENABLE_MODEL_ARMOR")
            if env_flag is not None:
                enable_model_armor = env_flag.lower() in ("true", "1", "yes")
            else:
                enable_model_armor = DEFAULT_CONFIG.enable_model_armor

        self.enable_model_armor = bool(enable_model_armor)
        self.model_armor_template = resolved_template
        self.model_armor_location = resolved_location
        self.max_chunk_chars = max_chunk_chars or DEFAULT_CONFIG.model_armor_max_chunk_chars
        self.chunk_overlap = chunk_overlap if chunk_overlap is not None else DEFAULT_CONFIG.model_armor_chunk_overlap

        if fail_closed is None:
            env_fc = os.getenv("MODEL_ARMOR_FAIL_CLOSED")
            self.fail_closed = (
                env_fc.lower() in ("true", "1", "yes")
                if env_fc is not None
                else DEFAULT_CONFIG.model_armor_fail_closed
            )
        else:
            self.fail_closed = bool(fail_closed)

        if scan_model_response_enabled is None:
            env_smr = os.getenv("MODEL_ARMOR_SCAN_MODEL_RESPONSE")
            self.scan_model_response_enabled = (
                env_smr.lower() in ("true", "1", "yes")
                if env_smr is not None
                else DEFAULT_CONFIG.model_armor_scan_model_response
            )
        else:
            self.scan_model_response_enabled = bool(scan_model_response_enabled)

        if enable_multilang is None:
            env_ml = os.getenv("MODEL_ARMOR_ENABLE_MULTILANG")
            self.enable_multilang = (
                env_ml.lower() in ("true", "1", "yes")
                if env_ml is not None
                else DEFAULT_CONFIG.model_armor_enable_multilang
            )
        else:
            self.enable_multilang = bool(enable_multilang)

        self._client: Optional[Any] = model_armor_client

    @property
    def is_model_armor_configured(self) -> bool:
        """Returns True when Model Armor is enabled and has a valid target template."""
        return bool(self.enable_model_armor and self.model_armor_template)

    def _get_model_armor_client(self) -> Any:
        """Returns cached or newly initialized regional ModelArmorClient."""
        if self._client is not None:
            return self._client

        from google.api_core.client_options import ClientOptions
        from google.cloud import modelarmor_v1

        endpoint = f"modelarmor.{self.model_armor_location}.rep.googleapis.com"
        self._client = modelarmor_v1.ModelArmorClient(
            transport="rest",
            client_options=ClientOptions(api_endpoint=endpoint),
        )
        return self._client

    def _normalize_text(self, text: str) -> str:
        """Normalizes text via HTML unescape, NFKC homoglyph folding, and invisible/bidi control removal."""
        if not text:
            return ""

        # 1. Decode HTML entities
        unescaped = html.unescape(text)
        # 2. Fold Unicode compatibility characters (fullwidth / mathematical lookalikes)
        folded = unicodedata.normalize("NFKC", unescaped)
        # 3. Strip zero-width spaces, soft hyphens, BOM, and bidirectional override characters
        cleaned = re.sub(r"[\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF\u00AD]", "", folded)
        return cleaned

    def _chunk_text(self, text: str) -> List[str]:
        """Splits large text into overlapping windows so boundary-split injections are scanned."""
        if len(text) <= self.max_chunk_chars:
            return [text]

        chunks: List[str] = []
        step = max(1, self.max_chunk_chars - self.chunk_overlap)
        start = 0
        while start < len(text):
            chunks.append(text[start : start + self.max_chunk_chars])
            if start + self.max_chunk_chars >= len(text):
                break
            start += step
        return chunks

    def _extract_decoded_obfuscations(self, text: str) -> List[Tuple[str, str]]:
        """Decodes suspicious URL-encoded or Base64-encoded spans for inspection."""
        decoded_candidates: List[Tuple[str, str]] = []

        # URL-encoded sequences containing at least 4 percent-encoded bytes
        if len(re.findall(r"%[0-9A-Fa-f]{2}", text)) >= 4:
            url_decoded = unquote(text)
            if url_decoded != text:
                decoded_candidates.append((url_decoded, "url_encoded_payload"))

        # Base64-like tokens >= 24 chars that decode cleanly to printable UTF-8
        for m in _BASE64_CANDIDATE_RE.finditer(text):
            token = m.group(0)
            padded = token + ("=" * ((4 - len(token) % 4) % 4))
            try:
                raw_bytes = base64.b64decode(padded, validate=True)
                decoded_str = raw_bytes.decode("utf-8")
                if decoded_str and sum(ch.isprintable() or ch.isspace() for ch in decoded_str) / len(decoded_str) > 0.9:
                    decoded_candidates.append((decoded_str, token[:60]))
            except Exception:
                continue

        return decoded_candidates

    def _build_multilang_metadata(self, modelarmor_v1: Any) -> Optional[Any]:
        """Constructs MultiLanguageDetectionMetadata if supported by the installed SDK."""
        if not self.enable_multilang:
            return None
        meta_cls = getattr(modelarmor_v1, "MultiLanguageDetectionMetadata", None)
        if meta_cls is None:
            return None
        return meta_cls(enable_multi_language_detection=True)

    def _parse_sanitization_result(
        self,
        sanitization_result: Any,
        source_text: str,
        engine_name: str = "model_armor",
    ) -> Optional[InjectionResult]:
        """Parses Model Armor `SanitizationResult` protobuf/object into an `InjectionResult`."""
        if sanitization_result is None:
            return None

        # Verify invocation status did not fail completely
        inv_res = getattr(sanitization_result, "invocation_result", None)
        if inv_res is not None and _enum_name(inv_res).endswith("FAILURE"):
            raise RuntimeError("Model Armor returned InvocationResult.FAILURE")

        triggered_filters: List[str] = []
        matched_uris: List[str] = []
        sdp_info_types: List[str] = []
        deidentified_text: Optional[str] = None

        overall_match = _match_state_is_found(getattr(sanitization_result, "filter_match_state", None))

        filter_results = getattr(sanitization_result, "filter_results", None) or {}
        items = filter_results.items() if isinstance(filter_results, dict) else []

        for _, f_res in items:
            # 1. Prompt Injection & Jailbreak filter
            pi_res = getattr(f_res, "pi_and_jailbreak_filter_result", None)
            if pi_res and _match_state_is_found(getattr(pi_res, "match_state", None)):
                conf = getattr(pi_res, "confidence_level", None)
                conf_name = getattr(conf, "name", str(conf)) if conf else ""
                tag = f"pi_and_jailbreak:{conf_name}" if conf_name else "pi_and_jailbreak"
                triggered_filters.append(tag)

            # 2. Malicious URI filter (plus matched URI extraction)
            uri_res = getattr(f_res, "malicious_uri_filter_result", None)
            if uri_res and _match_state_is_found(getattr(uri_res, "match_state", None)):
                triggered_filters.append("malicious_uri")
                for uri_item in getattr(uri_res, "malicious_uri_matched_items", None) or []:
                    uri_val = getattr(uri_item, "uri", None)
                    if uri_val and uri_val not in matched_uris:
                        matched_uris.append(uri_val)

            # 3. Sensitive Data Protection (SDP) filter (inspect, deidentify, redact)
            sdp_res = getattr(f_res, "sdp_filter_result", None)
            if sdp_res:
                insp = getattr(sdp_res, "inspect_result", None)
                deid = getattr(sdp_res, "deidentify_result", None)
                red = getattr(sdp_res, "redact_result", None)
                sdp_matched = any(
                    sub and _match_state_is_found(getattr(sub, "match_state", None))
                    for sub in (insp, deid, red)
                )
                if sdp_matched:
                    triggered_filters.append("sdp")
                if deid is not None:
                    deid_data = getattr(deid, "data", None)
                    deid_txt = getattr(deid_data, "text", None) if deid_data is not None else None
                    if deid_txt:
                        deidentified_text = deid_txt
                    for it in getattr(deid, "info_types", None) or []:
                        if it and str(it) not in sdp_info_types:
                            sdp_info_types.append(str(it))
                if insp is not None:
                    for finding in getattr(insp, "findings", None) or []:
                        info_type_obj = getattr(finding, "info_type", None)
                        it_name = getattr(info_type_obj, "name", None) or (str(info_type_obj) if info_type_obj else None)
                        if it_name and it_name not in sdp_info_types:
                            sdp_info_types.append(it_name)

            # 4. Responsible AI (RAI) filter (plus type breakdown)
            rai_res = getattr(f_res, "rai_filter_result", None)
            if rai_res and _match_state_is_found(getattr(rai_res, "match_state", None)):
                rai_types = getattr(rai_res, "rai_filter_type_results", None) or {}
                matched_subtypes = [
                    str(k)
                    for k, v in (rai_types.items() if isinstance(rai_types, dict) else [])
                    if _match_state_is_found(getattr(v, "match_state", None))
                ]
                if matched_subtypes:
                    triggered_filters.append(f"rai:{'+'.join(sorted(matched_subtypes))}")
                else:
                    triggered_filters.append("rai")

            # 5. CSAM & Virus scan filters
            csam_res = getattr(f_res, "csam_filter_filter_result", None)
            if csam_res and _match_state_is_found(getattr(csam_res, "match_state", None)):
                triggered_filters.append("csam")

            virus_res = getattr(f_res, "virus_scan_filter_result", None)
            if virus_res and _match_state_is_found(getattr(virus_res, "match_state", None)):
                triggered_filters.append("virus_scan")

        if not overall_match and not triggered_filters:
            return None

        if not triggered_filters:
            triggered_filters.append("model_armor_filter")

        # Determine primary pattern category
        if all(f.startswith("malicious_uri") for f in triggered_filters):
            pattern_type = InjectionPatternType.MALICIOUS_URI
        elif all(f == "sdp" for f in triggered_filters):
            pattern_type = InjectionPatternType.SENSITIVE_DATA_LEAK
        else:
            pattern_type = InjectionPatternType.MODEL_ARMOR_FLAGGED

        snippet = (matched_uris[0] if matched_uris else source_text[:100])
        return InjectionResult(
            detected=True,
            pattern_type=pattern_type,
            matched_snippet=snippet,
            sanitized_snippet=sanitize_snippet(snippet),
            confidence=0.99,
            engine=engine_name,
            triggered_filters=triggered_filters,
            model_armor_status="matched",
            matched_uris=matched_uris,
            sdp_info_types=sdp_info_types,
            deidentified_text=deidentified_text,
        )

    def scan_text(self, text: str) -> InjectionResult:
        """Scans text via Google Cloud Model Armor (primary) plus local defense-in-depth rules."""
        if not text or not text.strip():
            return InjectionResult(
                detected=False,
                engine="none",
                model_armor_status="disabled" if not self.enable_model_armor else "clean",
            )

        normalized = self._normalize_text(text)
        decoded_candidates = self._extract_decoded_obfuscations(normalized)
        ma_res: Optional[InjectionResult] = None
        ma_status = "disabled"
        ma_error: Optional[str] = None

        # 1. Primary Inspection: Google Cloud Model Armor (normalized chunks + decoded payloads)
        if self.enable_model_armor:
            if not self.model_armor_template:
                ma_status = "error"
                ma_error = "Model Armor is enabled but no template resource path is configured."
                logger.error(ma_error)
            else:
                ma_res = self._scan_with_model_armor(normalized, decoded_candidates=decoded_candidates)
                ma_status = ma_res.model_armor_status
                ma_error = ma_res.model_armor_error

        # 2. Defense-in-Depth: Local domain heuristics (verdict overrides, delimiter breakouts, secret patterns)
        local_res = self._scan_local_heuristics(
            normalized,
            ma_status=ma_status,
            ma_error=ma_error,
            decoded_candidates=decoded_candidates,
        )

        # Combine Model Armor primary detection + local rule evidence if both triggered
        if ma_res is not None and ma_res.detected:
            if local_res.detected:
                ma_res.engine = "model_armor+local_heuristic"
            return ma_res

        if local_res.detected:
            if ma_status == "clean":
                local_res.engine = "model_armor+local_heuristic"
            return local_res

        return InjectionResult(
            detected=False,
            engine="model_armor+local_heuristic" if ma_status == "clean" else "local_heuristic",
            model_armor_status=ma_status,
            model_armor_error=ma_error,
        )

    def _scan_local_heuristics(
        self,
        text: str,
        ma_status: str = "disabled",
        ma_error: Optional[str] = None,
        decoded_candidates: Optional[List[Tuple[str, str]]] = None,
    ) -> InjectionResult:
        """Evaluates normalized text and decoded obfuscations against local heuristic rules."""
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
                        model_armor_status=ma_status,
                        model_armor_error=ma_error,
                    )

        # Inspect decoded URL / Base64 payloads for obfuscated attacks
        candidates = decoded_candidates if decoded_candidates is not None else self._extract_decoded_obfuscations(text)
        for decoded_text, encoded_label in candidates:
            decoded_norm = self._normalize_text(decoded_text)
            for _, regex_list in _PATTERNS.items():
                for regex in regex_list:
                    match = regex.search(decoded_norm)
                    if match:
                        raw_snippet = f"obfuscated({encoded_label}): {match.group(0)}"
                        sanitized = sanitize_snippet(raw_snippet)
                        logger.warning(
                            "Encoded prompt injection detected (%s): '%s'",
                            encoded_label,
                            sanitized,
                        )
                        return InjectionResult(
                            detected=True,
                            pattern_type=InjectionPatternType.ENCODING_OBFUSCATION,
                            matched_snippet=raw_snippet,
                            sanitized_snippet=sanitized,
                            confidence=0.92,
                            engine="local_heuristic",
                            model_armor_status=ma_status,
                            model_armor_error=ma_error,
                        )

        return InjectionResult(
            detected=False,
            engine="local_heuristic",
            model_armor_status=ma_status,
            model_armor_error=ma_error,
        )

    def _scan_with_model_armor(
        self,
        text: str,
        decoded_candidates: Optional[List[Tuple[str, str]]] = None,
    ) -> InjectionResult:
        """Invokes regional Google Cloud Model Armor `sanitize_user_prompt` over chunks and decoded spans."""
        if not self.model_armor_template:
            return InjectionResult(
                detected=False,
                engine="local_heuristic",
                model_armor_status="error" if self.enable_model_armor else "disabled",
                model_armor_error="Model Armor template not configured" if self.enable_model_armor else None,
            )

        try:
            from google.cloud import modelarmor_v1

            client = self._get_model_armor_client()
            multilang_meta = self._build_multilang_metadata(modelarmor_v1)

            scan_payloads = list(self._chunk_text(text))
            for decoded_str, _ in decoded_candidates or []:
                norm_decoded = self._normalize_text(decoded_str)
                if norm_decoded.strip():
                    scan_payloads.extend(self._chunk_text(norm_decoded))

            for payload_chunk in scan_payloads:
                req_kwargs: dict[str, Any] = {
                    "name": self.model_armor_template,
                    "user_prompt_data": modelarmor_v1.DataItem(text=payload_chunk),
                }
                if multilang_meta is not None:
                    req_kwargs["multi_language_detection_metadata"] = multilang_meta
                request = modelarmor_v1.SanitizeUserPromptRequest(**req_kwargs)
                response = client.sanitize_user_prompt(request=request)
                parsed = self._parse_sanitization_result(
                    getattr(response, "sanitization_result", None),
                    source_text=payload_chunk,
                    engine_name="model_armor",
                )
                if parsed is not None:
                    logger.warning(
                        "Google Cloud Model Armor flagged user prompt (filters=%s, snippet='%s')",
                        parsed.triggered_filters,
                        parsed.sanitized_snippet,
                    )
                    return parsed

            return InjectionResult(detected=False, engine="model_armor", model_armor_status="clean")
        except Exception as e:
            err_msg = str(e)
            logger.error("Model Armor user-prompt inspection failed (%s)", err_msg)
            return InjectionResult(
                detected=False,
                engine="local_heuristic",
                model_armor_status="error",
                model_armor_error=err_msg,
            )

    def scan_model_response(self, response_text: str, user_prompt: str = "") -> InjectionResult:
        """Sanitizes LLM output via Model Armor `sanitize_model_response` and local exfiltration checks."""
        if not response_text or not response_text.strip():
            return InjectionResult(
                detected=False,
                engine="none",
                model_armor_status="disabled" if not self.enable_model_armor else "clean",
            )

        ma_status = "disabled"
        ma_error: Optional[str] = None
        ma_res: Optional[InjectionResult] = None

        if self.enable_model_armor:
            if not self.model_armor_template:
                ma_status = "error"
                ma_error = "Model Armor is enabled but no template resource path is configured."
            else:
                try:
                    from google.cloud import modelarmor_v1

                    client = self._get_model_armor_client()
                    multilang_meta = self._build_multilang_metadata(modelarmor_v1)
                    for chunk in self._chunk_text(response_text):
                        req_kwargs: dict[str, Any] = {
                            "name": self.model_armor_template,
                            "model_response_data": modelarmor_v1.DataItem(text=chunk),
                        }
                        if user_prompt:
                            req_kwargs["user_prompt"] = user_prompt[: self.max_chunk_chars]
                        if multilang_meta is not None:
                            req_kwargs["multi_language_detection_metadata"] = multilang_meta
                        request = modelarmor_v1.SanitizeModelResponseRequest(**req_kwargs)
                        response = client.sanitize_model_response(request=request)
                        parsed = self._parse_sanitization_result(
                            getattr(response, "sanitization_result", None),
                            source_text=chunk,
                            engine_name="model_armor",
                        )
                        if parsed is not None:
                            logger.warning(
                                "Google Cloud Model Armor flagged LLM model response (filters=%s)",
                                parsed.triggered_filters,
                            )
                            ma_res = parsed
                            ma_status = "matched"
                            break
                    if ma_res is None:
                        ma_status = "clean"
                except Exception as e:
                    ma_error = str(e)
                    logger.error("Model Armor model-response inspection failed (%s)", ma_error)
                    ma_status = "error"

        # Defense-in-depth local egress leak check (private keys, API tokens echoed into response)
        local_leak: Optional[InjectionResult] = None
        for regex in _MODEL_RESPONSE_EXFIL_PATTERNS:
            m = regex.search(response_text)
            if m:
                snippet = sanitize_snippet(m.group(0))
                logger.warning("Potential credential exfiltration detected in LLM output: '%s'", snippet)
                local_leak = InjectionResult(
                    detected=True,
                    pattern_type=InjectionPatternType.SENSITIVE_DATA_LEAK,
                    matched_snippet=m.group(0),
                    sanitized_snippet=snippet,
                    confidence=0.95,
                    engine="local_heuristic",
                    triggered_filters=["local_secret_egress"],
                    model_armor_status=ma_status,
                    model_armor_error=ma_error,
                )
                break

        if ma_res is not None and ma_res.detected:
            if local_leak is not None:
                ma_res.engine = "model_armor+local_heuristic"
                for flt in local_leak.triggered_filters:
                    if flt not in ma_res.triggered_filters:
                        ma_res.triggered_filters.append(flt)
            return ma_res

        if local_leak is not None:
            if ma_status == "clean":
                local_leak.engine = "model_armor+local_heuristic"
            return local_leak

        return InjectionResult(
            detected=False,
            engine="model_armor+local_heuristic" if ma_status == "clean" else "local_heuristic",
            model_armor_status=ma_status,
            model_armor_error=ma_error,
        )

    def quarantine_untrusted_text(
        self,
        text: str,
        injection_result: Optional[InjectionResult] = None,
    ) -> str:
        """Neutralizes adversarial directives & delimiter escapes before sending text to the LLM.

        Applies Model Armor SDP de-identified text when available, preserves genuine release-note
        lines so breaking API extraction continues working, and keeps unmodified raw release notes
        intact in caller scope for QuoteVerifier.
        """
        if not text:
            return ""

        working_text = text
        if injection_result is not None:
            deid = injection_result.deidentified_release_notes or injection_result.deidentified_text
            if deid:
                working_text = deid

        sanitized = self._normalize_text(working_text)

        # Defang delimiter breakout attempts inside HTML comments containing injection phrases
        def _clean_html_comment(match: re.Match[str]) -> str:
            inner = match.group(1)
            for regex_list in _PATTERNS.values():
                if any(rx.search(inner) for rx in regex_list):
                    return "[QUARANTINED_ADVERSARIAL_COMMENT]"
            return match.group(0)

        sanitized = _HTML_COMMENT_RE.sub(_clean_html_comment, sanitized)

        # Defang delimiter escape tags explicitly
        for rx in _PATTERNS[InjectionPatternType.DELIMITER_ESCAPE]:
            sanitized = rx.sub("[DEFANGED_DELIMITER]", sanitized)

        # Redact matched adversarial directives in-place without erasing legitimate changelog lines
        for p_type in (
            InjectionPatternType.INSTRUCTION_RESET,
            InjectionPatternType.FORCED_VERDICT_OVERRIDE,
            InjectionPatternType.SECRET_EXFILTRATION,
            InjectionPatternType.ROLEPLAY_JAILBREAK,
        ):
            for rx in _PATTERNS[p_type]:
                sanitized = rx.sub("[QUARANTINED_ADVERSARIAL_DIRECTIVE]", sanitized)

        # If Model Armor flagged release notes semantically (even without regex match), mark boundary
        if (
            injection_result is not None
            and injection_result.detected
            and "release_notes" in (injection_result.surfaces_flagged or [])
            and "[QUARANTINED_" not in sanitized
        ):
            flt_str = ", ".join(injection_result.triggered_filters or ["model_armor"])
            sanitized = f"[MODEL_ARMOR_QUARANTINED_INPUT filters={flt_str}]\n{sanitized}"

        return sanitized

    def scan_pr(
        self,
        pr_title: str = "",
        pr_body: str = "",
        release_notes: str = "",
        commit_messages: Optional[Sequence[str]] = None,
    ) -> InjectionResult:
        """Comprehensive scan across all untrusted entry points of a pull request."""
        surfaces: List[Tuple[str, str]] = [
            ("pr_title", pr_title),
            ("pr_body", pr_body),
        ]
        if commit_messages:
            for idx, msg in enumerate(commit_messages):
                surfaces.append((f"commit_message[{idx}]", msg))
        surfaces.append(("release_notes", release_notes))

        flagged_surfaces: List[str] = []
        combined_filters: List[str] = []
        combined_uris: List[str] = []
        combined_info_types: List[str] = []
        primary_detection: Optional[InjectionResult] = None
        deidentified_release_notes: Optional[str] = None

        ma_statuses: List[str] = []
        ma_errors: List[str] = []

        for surface_name, content in surfaces:
            if not content or not content.strip():
                continue
            res = self.scan_text(content)
            ma_statuses.append(res.model_armor_status)
            if res.model_armor_error:
                ma_errors.append(f"{surface_name}: {res.model_armor_error}")
            if surface_name == "release_notes" and res.deidentified_text:
                deidentified_release_notes = res.deidentified_text

            if res.detected:
                flagged_surfaces.append(surface_name)
                for flt in res.triggered_filters:
                    if flt not in combined_filters:
                        combined_filters.append(flt)
                for uri in res.matched_uris:
                    if uri not in combined_uris:
                        combined_uris.append(uri)
                for it in res.sdp_info_types:
                    if it not in combined_info_types:
                        combined_info_types.append(it)
                if primary_detection is None:
                    primary_detection = res
                elif "model_armor" in res.engine and "model_armor" not in primary_detection.engine:
                    primary_detection.engine = "model_armor+local_heuristic"

        # Determine overall Model Armor status across all scanned surfaces
        if "matched" in ma_statuses:
            overall_ma_status = "matched"
        elif "error" in ma_statuses:
            overall_ma_status = "error"
        elif "clean" in ma_statuses:
            overall_ma_status = "clean"
        else:
            overall_ma_status = "disabled" if not self.enable_model_armor else "clean"

        overall_ma_error = "; ".join(ma_errors) if ma_errors else None

        if primary_detection is not None:
            primary_detection.surfaces_flagged = flagged_surfaces
            primary_detection.triggered_filters = combined_filters
            primary_detection.matched_uris = combined_uris
            primary_detection.sdp_info_types = combined_info_types
            primary_detection.model_armor_status = overall_ma_status
            primary_detection.model_armor_error = overall_ma_error
            primary_detection.deidentified_release_notes = deidentified_release_notes
            return primary_detection

        return InjectionResult(
            detected=False,
            engine="model_armor+local_heuristic" if overall_ma_status == "clean" else "local_heuristic",
            model_armor_status=overall_ma_status,
            model_armor_error=overall_ma_error,
            deidentified_release_notes=deidentified_release_notes,
        )
