"""Unit tests for ASTScanner confidence tiers and usage detection."""

import pytest
from risk_agent.models.schemas import ConfidenceTier
from risk_agent.scanner.ast_scanner import ASTScanner


class TestASTScanner:
    def setup_method(self):
        self.scanner = ASTScanner()

    def test_direct_import_and_call_high_confidence(self):
        code = (
            "import data_transformer\n"
            "def run():\n"
            "    return data_transformer.transform_legacy('payload')\n"
        )
        matches = self.scanner.scan_code_string(
            code,
            target_modules=["data_transformer"],
            affected_api="data_transformer.transform_legacy",
        )
        assert len(matches) == 1
        assert matches[0].confidence_tier == ConfidenceTier.HIGH
        assert matches[0].matched_symbol == "transform_legacy"
        assert matches[0].match_type == "direct_call"

    def test_aliased_import_and_call_high_confidence(self):
        code = (
            "import logger_engine as log\n"
            "def record():\n"
            "    log.log_fatal('disk full')\n"
        )
        matches = self.scanner.scan_code_string(
            code,
            target_modules=["logger_engine"],
            affected_api="logger_engine.log_fatal",
        )
        assert len(matches) == 1
        assert matches[0].confidence_tier == ConfidenceTier.HIGH
        assert matches[0].matched_symbol == "log_fatal"

    def test_from_import_and_call_high_confidence(self):
        code = (
            "from math_solver import solve\n"
            "def compute():\n"
            "    return solve('x+1')\n"
        )
        matches = self.scanner.scan_code_string(
            code,
            target_modules=["math_solver"],
            affected_api="math_solver.solve",
        )
        # Should record from_import and from_import_call
        assert len(matches) >= 1
        assert any(m.confidence_tier == ConfidenceTier.HIGH for m in matches)
        assert any(m.match_type == "from_import_call" for m in matches)

    def test_untyped_attribute_call_medium_confidence(self):
        # Module is imported in file, but called on arbitrary object instance
        code = (
            "import math_solver\n"
            "def compute(custom_calc):\n"
            "    return custom_calc.solve('x+1')\n"
        )
        matches = self.scanner.scan_code_string(
            code,
            target_modules=["math_solver"],
            affected_api="math_solver.solve",
        )
        assert len(matches) == 1
        assert matches[0].confidence_tier == ConfidenceTier.MEDIUM
        assert matches[0].match_type == "untyped_attribute_call"

    def test_name_only_call_low_confidence(self):
        # Module is NOT imported in file, but symbol name matches
        code = (
            "def handle(obj):\n"
            "    return obj.solve('x+1')\n"
        )
        matches = self.scanner.scan_code_string(
            code,
            target_modules=["math_solver"],
            affected_api="math_solver.solve",
        )
        assert len(matches) == 1
        assert matches[0].confidence_tier == ConfidenceTier.LOW

    def test_unrelated_code_zero_matches(self):
        # Code calls bold(), but affected API is render_html_table
        code = (
            "from text_styler import bold\n"
            "def title():\n"
            "    return bold('Hello')\n"
        )
        matches = self.scanner.scan_code_string(
            code,
            target_modules=["text_styler"],
            affected_api="text_styler.render_html_table",
        )
        assert len(matches) == 0

