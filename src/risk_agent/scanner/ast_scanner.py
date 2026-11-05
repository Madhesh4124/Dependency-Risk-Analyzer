"""AST-based static usage scanner with confidence tiers."""

import ast
import os
import time
from pathlib import Path
from typing import Dict, List, Optional, Set
from risk_agent.config import DEFAULT_CONFIG
from risk_agent.models.schemas import ConfidenceTier, UsageMatch


EXCLUDED_DIRS = {
    ".git",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "__pycache__",
    "site-packages",
    "build",
    "dist",
    ".pytest_cache",
    ".ruff_cache",
}


class FileUsageVisitor(ast.NodeVisitor):
    """AST visitor that tracks module imports and matches API usages with confidence tiers."""

    def __init__(self, target_modules: List[str], target_symbol: str, file_path: str):
        self.target_modules = set(target_modules)
        self.target_symbol = target_symbol
        self.file_path = file_path
        self.matches: List[UsageMatch] = []

        # Maps local identifier -> module name
        self.module_aliases: Dict[str, str] = {}
        # Maps local identifier -> imported target symbol
        self.symbol_aliases: Dict[str, str] = {}
        self.has_target_module_imported = False

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            base_mod = alias.name.split(".")[0]
            if alias.name in self.target_modules or base_mod in self.target_modules:
                local_name = alias.asname if alias.asname else alias.name
                self.module_aliases[local_name] = alias.name
                self.has_target_module_imported = True
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if not node.module:
            self.generic_visit(node)
            return

        base_mod = node.module.split(".")[0]
        if node.module in self.target_modules or base_mod in self.target_modules:
            self.has_target_module_imported = True
            for alias in node.names:
                if alias.name == self.target_symbol:
                    local_name = alias.asname if alias.asname else alias.name
                    self.symbol_aliases[local_name] = alias.name
                    self.matches.append(
                        UsageMatch(
                            file_path=self.file_path,
                            line_number=node.lineno,
                            matched_symbol=self.target_symbol,
                            match_type="from_import",
                            confidence_tier=ConfidenceTier.HIGH,
                            code_snippet=f"from {node.module} import {alias.name}",
                        )
                    )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        # 1. Direct call on imported module: e.g. alias.target_symbol(...)
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                obj_name = node.func.value.id
                attr_name = node.func.attr
                if attr_name == self.target_symbol:
                    if obj_name in self.module_aliases:
                        self.matches.append(
                            UsageMatch(
                                file_path=self.file_path,
                                line_number=node.lineno,
                                matched_symbol=self.target_symbol,
                                match_type="direct_call",
                                confidence_tier=ConfidenceTier.HIGH,
                                code_snippet=f"{obj_name}.{attr_name}(...)",
                            )
                        )
                    elif self.has_target_module_imported:
                        # Module was imported in file, but called on arbitrary object
                        self.matches.append(
                            UsageMatch(
                                file_path=self.file_path,
                                line_number=node.lineno,
                                matched_symbol=self.target_symbol,
                                match_type="untyped_attribute_call",
                                confidence_tier=ConfidenceTier.MEDIUM,
                                code_snippet=f"{obj_name}.{attr_name}(...)",
                            )
                        )
                    else:
                        # Name matches target symbol, but module not imported
                        self.matches.append(
                            UsageMatch(
                                file_path=self.file_path,
                                line_number=node.lineno,
                                matched_symbol=self.target_symbol,
                                match_type="name_only_call",
                                confidence_tier=ConfidenceTier.LOW,
                                code_snippet=f"{obj_name}.{attr_name}(...)",
                            )
                        )

        # 2. Call on from-imported symbol: e.g. target_symbol(...)
        elif isinstance(node.func, ast.Name):
            func_name = node.func.id
            if func_name in self.symbol_aliases:
                self.matches.append(
                    UsageMatch(
                        file_path=self.file_path,
                        line_number=node.lineno,
                        matched_symbol=self.target_symbol,
                        match_type="from_import_call",
                        confidence_tier=ConfidenceTier.HIGH,
                        code_snippet=f"{func_name}(...)",
                    )
                )

        self.generic_visit(node)


class ASTScanner:
    """Scans Python files in a directory snapshot for potential API usages."""

    def __init__(
        self,
        max_file_bytes: int = DEFAULT_CONFIG.scanner_max_file_bytes,
        max_file_count: int = DEFAULT_CONFIG.scanner_max_file_count,
        timeout_seconds: float = DEFAULT_CONFIG.scanner_timeout_seconds,
    ):
        self.max_file_bytes = max_file_bytes
        self.max_file_count = max_file_count
        self.timeout_seconds = timeout_seconds

    def scan_code_string(
        self,
        code_string: str,
        target_modules: List[str],
        affected_api: str,
        file_path: str = "snippet.py",
    ) -> List[UsageMatch]:
        """Scans a single string of Python source code."""
        target_symbol = affected_api.split(".")[-1]
        try:
            tree = ast.parse(code_string, filename=file_path)
        except SyntaxError:
            return []

        visitor = FileUsageVisitor(target_modules, target_symbol, file_path)
        visitor.visit(tree)
        return visitor.matches

    def scan_directory(
        self,
        root_dir: Path,
        target_modules: List[str],
        affected_api: str,
    ) -> List[UsageMatch]:
        """Walks directory and scans all eligible Python files for usages."""
        target_symbol = affected_api.split(".")[-1]
        all_matches: List[UsageMatch] = []
        files_scanned = 0
        start_time = time.time()

        for dirpath, dirnames, filenames in os.walk(root_dir):
            # Prune excluded directories
            dirnames[:] = [d for d in dirnames if d not in EXCLUDED_DIRS]

            for filename in filenames:
                if not filename.endswith(".py"):
                    continue

                if files_scanned >= self.max_file_count:
                    break
                if time.time() - start_time > self.timeout_seconds:
                    break

                file_path = Path(dirpath) / filename
                rel_path = str(file_path.relative_to(root_dir)).replace("\\", "/")

                try:
                    stat = file_path.stat()
                    if stat.st_size > self.max_file_bytes:
                        continue

                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()

                    # Skip binary null bytes
                    if "\x00" in content:
                        continue

                    tree = ast.parse(content, filename=rel_path)
                    visitor = FileUsageVisitor(target_modules, target_symbol, rel_path)
                    visitor.visit(tree)
                    all_matches.extend(visitor.matches)
                    files_scanned += 1
                except Exception:
                    continue

        return all_matches

