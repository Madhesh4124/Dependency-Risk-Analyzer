"""Quote verifier using normalized token-sequence matching."""

import re
from typing import List, Tuple
from risk_agent.config import DEFAULT_CONFIG
from risk_agent.models.schemas import QuoteVerificationResult


def tokenize(text: str) -> List[str]:
    """Tokenizes text into a normalized list of words/symbols.

    Strips markdown formatting (backticks, bullets, asterisks) and normalizes whitespace
    while preserving alphanumeric tokens and identifiers (including underscores and dots).
    """
    if not text:
        return []

    # Strip markdown code backticks and formatting symbols
    cleaned = re.sub(r"[`*_~#\-]+", " ", text)
    # Extract words, identifiers, and version strings
    tokens = re.findall(r"[a-zA-Z0-9_\.]+", cleaned)
    return [t.lower() for t in tokens]


class QuoteVerifier:
    """Verifies that an extracted quote originates verbatim from upstream release notes."""

    def __init__(self, min_token_length: int = DEFAULT_CONFIG.min_quote_token_length):
        self.min_token_length = min_token_length

    def verify_quote(
        self,
        quote: str,
        source_text: str,
        claim_id: str = "claim-1"
    ) -> QuoteVerificationResult:
        """Verifies quote against source text using contiguous normalized token sequence matching."""
        if not quote or not quote.strip():
            return QuoteVerificationResult(
                claim_id=claim_id,
                quoted_text=quote or "",
                is_verified=False,
                token_count=0,
                failure_reason="Quote is empty",
            )

        quote_tokens = tokenize(quote)
        token_count = len(quote_tokens)

        # Enforce minimum token floor
        if token_count < self.min_token_length:
            return QuoteVerificationResult(
                claim_id=claim_id,
                quoted_text=quote,
                is_verified=False,
                token_count=token_count,
                failure_reason=(
                    f"Quote token count ({token_count}) is below minimum floor ({self.min_token_length})"
                ),
            )

        if not source_text or not source_text.strip():
            return QuoteVerificationResult(
                claim_id=claim_id,
                quoted_text=quote,
                is_verified=False,
                token_count=token_count,
                failure_reason="Source release notes are empty or missing",
            )

        source_tokens = tokenize(source_text)

        # Search for contiguous sublist match
        q_len = len(quote_tokens)
        s_len = len(source_tokens)

        if q_len > s_len:
            return QuoteVerificationResult(
                claim_id=claim_id,
                quoted_text=quote,
                is_verified=False,
                token_count=token_count,
                failure_reason="Quote is longer than source text",
            )

        found = False
        for i in range(s_len - q_len + 1):
            if source_tokens[i : i + q_len] == quote_tokens:
                found = True
                break

        if found:
            return QuoteVerificationResult(
                claim_id=claim_id,
                quoted_text=quote,
                is_verified=True,
                token_count=token_count,
                failure_reason=None,
            )
        else:
            return QuoteVerificationResult(
                claim_id=claim_id,
                quoted_text=quote,
                is_verified=False,
                token_count=token_count,
                failure_reason="Normalized quote tokens not found in source text",
            )

