"""Phase 7: Five-Way Comparative Evaluation Baselines.

Defines:
1. Baseline 1 — SemVer Heuristic (Industry rule-of-thumb: MAJOR = RISKY, MINOR/PATCH = NO_RISK_FOUND)
2. Baseline 2 — Green CI Parity (Blind trust in CI: head_ci_status == SUCCESS -> NO_RISK_FOUND, else RISKY)
3. Baseline 3 — Pure AST Static Code Analysis (Syntax inspection only, without changelog comprehension)
4. Baseline 4 — Direct Single LLM Call (Ungrounded prompt to Gemini without quote verifier or risk floor)
5. System 5   — Full Hybrid Risk Agent Pipeline (Deterministic AST Floor + Grounded Gemini LLM + Token Quote Verifier)
"""

import ast
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from risk_agent.baselines import SingleCallEvaluationResponse, SingleCallLLMBaseline
from risk_agent.models.schemas import SeverityVerdict, VersionBumpType
from risk_agent.resolver.package_resolver import PackageResolver

logger = logging.getLogger("risk_agent.benchmark.baselines_5way")


class SemVerBaseline:
    """Baseline 1: Industry rule-of-thumb heuristic based strictly on Semantic Versioning."""

    def evaluate(self, bump_type: str, old_version: str = "", new_version: str = "") -> SeverityVerdict:
        b = (bump_type or "").upper()
        if b == "MAJOR":
            return SeverityVerdict.RISKY
        return SeverityVerdict.NO_RISK_FOUND


class GreenCIBaseline:
    """Baseline 2: Blind trust in PR CI test suite status."""

    def evaluate(self, head_ci_status: Optional[str]) -> SeverityVerdict:
        status = (head_ci_status or "").upper()
        if status == "SUCCESS":
            return SeverityVerdict.NO_RISK_FOUND
        return SeverityVerdict.RISKY


class PureASTBaseline:
    """Baseline 3: Pure AST static analysis without changelog comprehension.
    
    If the repository imports the updated package and references any symbol/attribute,
    it assumes risk (RISKY if direct call, REVIEW if imported, NO_RISK_FOUND if unused).
    """

    def __init__(self):
        self.resolver = PackageResolver

    def evaluate_code(self, package_name: str, repo_code_map: Dict[str, str]) -> SeverityVerdict:
        """Evaluates an in-memory dictionary of {filename: file_content}."""
        resolution = self.resolver.resolve(package_name)
        target_modules = set(resolution.import_module_names)

        has_import = False
        has_symbol_call = False

        for fname, content in repo_code_map.items():
            if not content.strip():
                continue
            try:
                tree = ast.parse(content, filename=fname)
            except Exception:
                continue

            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        base = alias.name.split(".")[0]
                        if alias.name in target_modules or base in target_modules:
                            has_import = True
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        base = node.module.split(".")[0]
                        if node.module in target_modules or base in target_modules:
                            has_import = True
                            if node.names:
                                has_symbol_call = True
                elif isinstance(node, ast.Attribute):
                    if isinstance(node.value, ast.Name):
                        if node.value.id in target_modules:
                            has_symbol_call = True

        if has_symbol_call:
            return SeverityVerdict.RISKY
        if has_import:
            return SeverityVerdict.REVIEW
        return SeverityVerdict.NO_RISK_FOUND

    def evaluate_directory(self, package_name: str, repo_dir: Path) -> SeverityVerdict:
        code_map = {}
        for pyfile in repo_dir.glob("**/*.py"):
            try:
                code_map[pyfile.name] = pyfile.read_text(encoding="utf-8")
            except Exception:
                continue
        return self.evaluate_code(package_name, code_map)
