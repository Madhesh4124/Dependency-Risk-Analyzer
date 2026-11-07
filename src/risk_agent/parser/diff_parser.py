"""Manifest and PR diff parser for dependency update detection."""

import logging
import re
import tomllib
from typing import Dict, List, Optional, Tuple
from packaging.requirements import Requirement, InvalidRequirement
from packaging.version import Version, InvalidVersion
from risk_agent.models.schemas import DependencyBump, VersionBumpType

logger = logging.getLogger(__name__)


def canonicalize_name(name: str) -> str:
    """Canonicalize a package name per PEP 503."""
    return re.sub(r"[-_.]+", "-", name).lower().strip()


def determine_bump_type(old_ver_str: str, new_ver_str: str) -> VersionBumpType:
    """Determines whether a version bump is MAJOR, MINOR, or PATCH."""
    try:
        old_v = Version(old_ver_str)
        new_v = Version(new_ver_str)
    except InvalidVersion:
        return VersionBumpType.UNKNOWN

    if new_v.major != old_v.major:
        return VersionBumpType.MAJOR
    if new_v.minor != old_v.minor:
        return VersionBumpType.MINOR
    if new_v.micro != old_v.micro:
        return VersionBumpType.PATCH
    return VersionBumpType.PATCH


class ManifestDiffParser:
    """Parses manifest file changes to extract exact dependency version updates."""

    # Matches requirements.txt specifiers like pkg==1.2.3 or pkg>=1.0.0
    REQ_LINE_PATTERN = re.compile(
        r"^\s*([a-zA-Z0-9_\-\.]+)\s*(?:===|==|>=|<=|~=|>|<)?\s*([0-9a-zA-Z\.\-_+]*)"
    )

    # Matches PEP 621 or Poetry dependencies in pyproject.toml
    TOML_DEP_PATTERN = re.compile(
        r'["\']([a-zA-Z0-9_\-\.]+)\s*(?:===|==|>=|<=|~=|>|<)\s*([0-9a-zA-Z\.\-_+]*)["\']'
    )

    @classmethod
    def parse_requirements_content(cls, content: str) -> Dict[str, str]:
        """Extracts {canonical_package_name: version_string} from requirements.txt content."""
        packages = {}
        for raw_line in content.splitlines():
            line = raw_line.strip()
            # Ignore comments, options, empty lines
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            # Strip comments and environment markers
            line = line.split("#")[0].split(";")[0].strip()
            # Strip --hash options
            line = re.sub(r"--hash=\S+", "", line).strip()

            match = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*(?:==|===|~=)\s*([0-9a-zA-Z\.\-_+]+)", line)
            if match:
                pkg_name, version = match.groups()
                packages[canonicalize_name(pkg_name)] = version.strip()
        return packages

    @classmethod
    def parse_pyproject_content(cls, content: str) -> Dict[str, str]:
        """Extracts {canonical_package_name: version_string} from pyproject.toml content.

        Supports:
        - PEP 621: [project.dependencies] and [project.optional-dependencies]
        - Poetry: [tool.poetry.dependencies] and [tool.poetry.group.*.dependencies]
        - Pipenv / Flit / generic string specifiers
        - Regex fallback for comments or unparseable partial diffs
        """
        packages: Dict[str, str] = {}
        if not content.strip():
            return packages

        # 1. Structural TOML parsing (standard, robust, format-agnostic)
        try:
            data = tomllib.loads(content)
            # PEP 621 dependencies
            project = data.get("project", {})
            if isinstance(project, dict):
                deps = project.get("dependencies", [])
                if isinstance(deps, list):
                    for item in deps:
                        if isinstance(item, str):
                            cls._extract_pep508_requirement(item, packages)

                opt_deps = project.get("optional-dependencies", {})
                if isinstance(opt_deps, dict):
                    for group_deps in opt_deps.values():
                        if isinstance(group_deps, list):
                            for item in group_deps:
                                if isinstance(item, str):
                                    cls._extract_pep508_requirement(item, packages)

            # Poetry dependencies
            tool = data.get("tool", {})
            if isinstance(tool, dict):
                poetry = tool.get("poetry", {})
                if isinstance(poetry, dict):
                    p_deps = poetry.get("dependencies", {})
                    if isinstance(p_deps, dict):
                        for pkg, spec in p_deps.items():
                            if pkg.lower() != "python":
                                cls._extract_poetry_spec(pkg, spec, packages)

                    groups = poetry.get("group", {})
                    if isinstance(groups, dict):
                        for g in groups.values():
                            if isinstance(g, dict):
                                g_deps = g.get("dependencies", {})
                                if isinstance(g_deps, dict):
                                    for pkg, spec in g_deps.items():
                                        cls._extract_poetry_spec(pkg, spec, packages)
        except Exception as e:
            logger.debug(f"tomllib parsing failed or partial TOML diff: {e}")

        # 2. Regex fallback: Catches unparseable diffs or unconventional formats
        for match in cls.TOML_DEP_PATTERN.finditer(content):
            pkg, ver = match.groups()
            canon_pkg = canonicalize_name(pkg)
            if ver and canon_pkg not in packages:
                packages[canon_pkg] = ver.strip()

        return packages

    @classmethod
    def _extract_pep508_requirement(cls, raw_req: str, out_dict: Dict[str, str]) -> None:
        """Parses a PEP 508 requirement string like 'pydantic==2.6.0' or 'fastapi>=0.100'."""
        try:
            req = Requirement(raw_req)
            name = canonicalize_name(req.name)
            for spec in req.specifier:
                out_dict[name] = str(spec.version)
                return
        except InvalidRequirement:
            pass
        # Fallback to simple split
        match = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*(?:===|==|>=|<=|~=|>|<)?\s*([0-9a-zA-Z\.\-_+]*)", raw_req)
        if match:
            pkg, ver = match.groups()
            if ver:
                out_dict[canonicalize_name(pkg)] = ver.strip()

    @classmethod
    def _extract_poetry_spec(cls, pkg_name: str, spec: object, out_dict: Dict[str, str]) -> None:
        """Extracts version from Poetry style dependencies (string, dict with version, etc)."""
        name = canonicalize_name(pkg_name)
        ver_str = ""
        if isinstance(spec, str):
            ver_str = spec
        elif isinstance(spec, dict) and "version" in spec:
            ver_str = str(spec["version"])

        if ver_str:
            clean_ver = re.sub(r"^[\^~>=<]+", "", ver_str).strip()
            if clean_ver:
                out_dict[name] = clean_ver

    @classmethod
    def parse_setup_cfg_content(cls, content: str) -> Dict[str, str]:
        """Extracts dependencies from setup.cfg install_requires."""
        packages = {}
        in_install_requires = False
        for raw_line in content.splitlines():
            line = raw_line.strip()
            if line.startswith("install_requires"):
                in_install_requires = True
                continue
            if in_install_requires:
                if line.startswith("[") or (line and not raw_line.startswith(" ")):
                    in_install_requires = False
                    continue
                match = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*(?:==|===|~=)\s*([0-9a-zA-Z\.\-_+]+)", line)
                if match:
                    pkg, ver = match.groups()
                    packages[canonicalize_name(pkg)] = ver.strip()
        return packages

    @classmethod
    def parse_file_pair(
        cls, filename: str, before_content: str, after_content: str
    ) -> List[DependencyBump]:
        """Compares before and after file content and returns detected version bumps."""
        fn = filename.lower()
        if "requirements" in fn or fn.endswith(".txt") or fn.endswith(".in"):
            old_pkgs = cls.parse_requirements_content(before_content)
            new_pkgs = cls.parse_requirements_content(after_content)
        elif "pyproject.toml" in fn:
            old_pkgs = cls.parse_pyproject_content(before_content)
            new_pkgs = cls.parse_pyproject_content(after_content)
        elif "setup.cfg" in fn:
            old_pkgs = cls.parse_setup_cfg_content(before_content)
            new_pkgs = cls.parse_setup_cfg_content(after_content)
        else:
            return []

        bumps = []
        for pkg, new_ver in new_pkgs.items():
            if pkg in old_pkgs:
                old_ver = old_pkgs[pkg]
                if old_ver != new_ver:
                    bump_type = determine_bump_type(old_ver, new_ver)
                    bumps.append(
                        DependencyBump(
                            package_name=pkg,
                            old_version=old_ver,
                            new_version=new_ver,
                            manifest_file=filename,
                            bump_type=bump_type,
                        )
                    )
        return bumps

    @classmethod
    def parse_unified_diff(cls, filename: str, patch_text: str) -> List[DependencyBump]:
        """Parses a unified git patch diff to identify dependency bumps."""
        removed_lines = []
        added_lines = []

        for line in patch_text.splitlines():
            if line.startswith("---") or line.startswith("+++") or line.startswith("@@"):
                continue
            if line.startswith("-"):
                removed_lines.append(line[1:])
            elif line.startswith("+"):
                added_lines.append(line[1:])

        return cls.parse_file_pair(
            filename,
            before_content="\n".join(removed_lines),
            after_content="\n".join(added_lines),
        )

