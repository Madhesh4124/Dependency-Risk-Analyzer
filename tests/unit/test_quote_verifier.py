"""Unit tests for QuoteVerifier normalized token-sequence matching and floors."""

import pytest
from risk_agent.verifier.quote_verifier import QuoteVerifier, tokenize


class TestQuoteVerifier:
    def setup_method(self):
        self.verifier = QuoteVerifier(min_token_length=6)
        self.source = (
            "## Release Notes 2.0.0\n\n"
            "### Breaking Changes\n"
            "- Removed `transform_legacy()` in favor of `transform()`. "
            "Any calls to `transform_legacy()` will raise an AttributeError.\n"
            "- Dropped compatibility shims for Python 3.8.\n"
        )

    def test_exact_match(self):
        quote = "Removed `transform_legacy()` in favor of `transform()`."
        res = self.verifier.verify_quote(quote, self.source)
        assert res.is_verified is True
        assert res.token_count >= 6
        assert res.failure_reason is None

    def test_markdown_and_linebreak_variants_pass(self):
        # Quote with line break and without backticks
        quote = (
            "Removed transform_legacy() in\n"
            "favor of transform(). Any calls to transform_legacy()"
        )
        res = self.verifier.verify_quote(quote, self.source)
        assert res.is_verified is True

    def test_near_match_fails(self):
        # Paraphrased / slightly hallucinated
        quote = "Removed legacy transform functions in favor of transform method."
        res = self.verifier.verify_quote(quote, self.source)
        assert res.is_verified is False
        assert "not found in source" in res.failure_reason

    def test_token_count_below_floor_fails(self):
        # Only 3 tokens: below floor of 6
        short_quote = "Removed transform_legacy() method."
        assert len(tokenize(short_quote)) < 6
        res = self.verifier.verify_quote(short_quote, self.source)
        assert res.is_verified is False
        assert "below minimum floor" in res.failure_reason

    def test_empty_quote_fails(self):
        res = self.verifier.verify_quote("", self.source)
        assert res.is_verified is False
        assert "empty" in res.failure_reason

    def test_empty_source_fails(self):
        quote = "Removed transform_legacy in favor of modern transform."
        res = self.verifier.verify_quote(quote, "")
        assert res.is_verified is False
        assert "empty or missing" in res.failure_reason

