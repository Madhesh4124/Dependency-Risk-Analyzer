#!/usr/bin/env python3
"""
Tier B Benchmark Candidate Collector (v3)
=========================================
Screens public GitHub dependency-update PRs and decides whether each is a clean
candidate for OFFLINE differential replay (old-dependency tests vs new-dependency tests).

What this script does NOT do
----------------------------
* It does not assign ground-truth labels. `ground_truth_label` is always None here;
  only the (separate) replay harness may set it.
* It does not run any repository or package code.

Design rules
------------
* Dependency changes are derived by PARSING THE FILES AT THE BEFORE/AFTER COMMITS
  (tomllib / json / `packaging`), not by regex over diff hunks. Truncated or missing
  patches, partial hunks and context-window effects therefore cannot hide changes.
* "Before" = merge-base of base and head (from the compare API), not `pr.base.sha`.
* Ambiguity -> INCONCLUSIVE, rule violations -> REJECTED, API/infra failures -> ERROR.
  An API failure is never recorded as a REJECTED candidate.
* Only resolved versions count: `==` pins or lockfile versions. Range specifiers
  (`>=1.0`) without a lockfile are INCONCLUSIVE (tests would run at an unknown version).
* CI is observational. It is used only as a pre-filter ("old state plausibly green"),
  never to infer a label. `model_visible_view()` strips everything outcome-related.
* Output batches are write-once (GCS `if_generation_match=0`, Firestore `create()`).

Requires Python >= 3.11 (tomllib) or `pip install tomli`.
"""

from __future__ import annotations

import argparse
import configparser
import hashlib
import json
import logging
import os
import re
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Generator, List, Optional, Set, Tuple
from urllib.parse import quote

import httpx
from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore[no-redef]

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("tier_b_collector")

SCHEMA_VERSION = "3.0"
MAX_PR_FILES = 3000  # GitHub's hard cap for the PR files endpoint
MAX_FILE_BYTES = 20 * 1024 * 1024
MIN_PYTHON_SHARE_DEFAULT = 0.10

GITHUB_TOKEN = (
    os.getenv("GITHUB_TOKEN") or os.getenv("github-token") or os.getenv("github_token") or ""
)
GCS_BUCKET_NAME = os.getenv("GCS_BUCKET_NAME", "")
FIRESTORE_PROJECT_ID = os.getenv("FIRESTORE_PROJECT_ID", os.getenv("GOOGLE_CLOUD_PROJECT", ""))
BATCH_OUTPUT_DIR = os.getenv("BATCH_OUTPUT_DIR", "tier_b/batches")
MANIFEST_OUTPUT_DIR = os.getenv("MANIFEST_OUTPUT_DIR", "tier_b/manifests")


class GitHubAPIError(RuntimeError):
    """Infrastructure/API failure. Must never be recorded as a REJECTED candidate."""


class ParseError(ValueError):
    """A manifest or lockfile could not be read or parsed."""


# =====================================================================
# Domain data classes
# =====================================================================


@dataclass
class VersionBump:
    package_name: str  # canonicalized
    raw_package_name: str
    old_version: str
    new_version: str
    bump_type: str  # major | minor | patch | prerelease_or_post | downgrade | same | unknown
    is_valid_pep440: bool
    is_calver: bool  # heuristic: first release component >= 2000
    is_zero_major: bool  # 0.x: minor bumps are conventionally breaking
    involves_prerelease: bool
    resolution_source: str  # "lockfile" | "direct_pin"
    manifest_source: str


@dataclass
class ManifestAnalysis:
    direct_manifest_files: List[str]
    lockfile_files: List[str]
    non_manifest_files: List[str]
    canonical_packages_modified: List[str]
    exactly_one_dependency_updated: bool
    lockfile_status: str  # NO_LOCKFILE | CONFIRMED_ISOLATED | COMPANION_ISOLATED | UNRESOLVED_LOCKFILE_CHANGE | UNPARSEABLE_LOCKFILE
    transitive_confound_risk: str  # LOW | HIGH | UNKNOWN
    notes: List[str] = field(default_factory=list)
    aux_manifest_files: List[str] = field(default_factory=list)
    unparseable_files: List[str] = field(default_factory=list)
    rejections: List[str] = field(default_factory=list)
    inconclusive_codes: List[str] = field(default_factory=list)


@dataclass
class CIEvidence:
    """Observational only. Never model-visible, never used to derive a label."""

    api_base_sha: str
    merge_base_sha: str
    head_sha: str
    base_ci_status: str  # SUCCESS | FAILURE | UNKNOWN (evaluated at merge_base_sha)
    head_ci_status: str
    base_checks_count: int
    head_checks_count: int
    base_failed_checks: List[str]
    head_failed_checks: List[str]
    base_test_like_checks: List[str]


@dataclass
class TestEvidence:
    tests_present: bool
    test_file_count: int
    tree_truncated: bool


@dataclass
class ValidationChecklist:
    python_repo_verified: bool
    single_dependency_verified: bool
    versions_resolved: bool
    no_non_manifest_code_edits: bool
    commit_shas_captured: bool
    lockfile_confound_free: bool
    tests_present: bool
    base_ci_status: str
    pr_merged: bool
    ready_for_differential_replay: bool


@dataclass
class CandidateRecord:
    case_id: str
    collection_status: str  # ACCEPTED_CANDIDATE | REJECTED | INCONCLUSIVE | ERROR
    rejection_reasons: List[str]
    inconclusive_reasons: List[str]
    collected_at: str
    repository: Dict[str, Any]
    pull_request: Dict[str, Any]
    dependency_bump: Optional[Dict[str, Any]]
    companion_bumps: List[Dict[str, Any]]
    manifest_analysis: Dict[str, Any]
    ci_evidence: Dict[str, Any]
    test_evidence: Dict[str, Any]
    validation_checklist: Dict[str, Any]
    inconclusive_reason: Optional[str] = None
    error: Optional[str] = None
    ground_truth_label: Optional[str] = None  # ALWAYS None here; set only by replay
    schema_version: str = SCHEMA_VERSION


# =====================================================================
# GitHub client: strict failures, pagination, rate-limit handling
# =====================================================================


class GitHubClient:
    BASE_URL = "https://api.github.com"

    def __init__(
        self,
        token: Optional[str] = None,
        max_retries: int = 5,
        max_rate_limit_wait: float = 60.0,
    ):
        self.token = token or GITHUB_TOKEN
        if not self.token:
            try:
                import subprocess

                res = subprocess.run(["gh", "auth", "token"], capture_output=True, text=True)
                if res.returncode == 0 and res.stdout.strip():
                    self.token = res.stdout.strip()
            except Exception:
                pass

        self.max_retries = max_retries
        self.max_rate_limit_wait = max_rate_limit_wait
        headers = {
            "User-Agent": "TierB-Benchmark-Collector/3.0",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
            masked = f"...{self.token[-4:]}" if len(self.token) >= 4 else "****"
            logger.info("GitHub client authenticated with token (%s)", masked)
        else:
            logger.warning("No GitHub token found; unauthenticated limit is 60 req/hr.")
        self._client = httpx.Client(headers=headers, timeout=30.0)

    @staticmethod
    def _is_rate_limited(resp: httpx.Response) -> bool:
        if resp.status_code == 429:
            return True
        if resp.status_code == 403:
            if resp.headers.get("x-ratelimit-remaining") == "0" or resp.headers.get("retry-after"):
                return True
            return "rate limit" in resp.text.lower()
        return False

    @staticmethod
    def _rate_limit_wait(resp: httpx.Response, fallback: float) -> float:
        retry_after = resp.headers.get("retry-after")
        reset = resp.headers.get("x-ratelimit-reset")
        if retry_after:
            return max(float(retry_after), 1.0)
        if reset:
            return max(float(reset) - time.time() + 1.0, 1.0)
        return max(fallback, 1.0)

    def request(
        self,
        method: str,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> httpx.Response:
        url = endpoint if endpoint.startswith("http") else f"{self.BASE_URL}/{endpoint.lstrip('/')}"
        delay = 2.0
        for attempt in range(1, self.max_retries + 1):
            try:
                resp = self._client.request(method, url, params=params, headers=headers)
            except (httpx.TimeoutException, httpx.NetworkError) as err:
                if attempt == self.max_retries:
                    raise GitHubAPIError(f"Network failure for {url}: {err}") from err
                logger.warning("Network error (%s); retry in %.1fs", err, delay)
                time.sleep(delay)
                delay *= 2
                continue

            if self._is_rate_limited(resp):
                wait = self._rate_limit_wait(resp, delay)
                if wait > self.max_rate_limit_wait:
                    raise GitHubAPIError(
                        f"Rate limited; required wait {wait:.0f}s exceeds cap {self.max_rate_limit_wait:.0f}s"
                    )
                if attempt == self.max_retries:
                    raise GitHubAPIError("Rate limit retries exhausted")
                logger.warning("Rate limited (HTTP %s); sleeping %.1fs", resp.status_code, wait)
                time.sleep(wait)
                delay *= 2
                continue

            if 500 <= resp.status_code < 600:
                if attempt == self.max_retries:
                    raise GitHubAPIError(f"HTTP {resp.status_code} from {url} after retries")
                logger.warning("Server error HTTP %s; retry in %.1fs", resp.status_code, delay)
                time.sleep(delay)
                delay *= 2
                continue

            return resp
        raise GitHubAPIError(f"Request loop exited unexpectedly for {url}")  # pragma: no cover

    def get_json(
        self, endpoint: str, params: Optional[Dict[str, Any]] = None, allow_404: bool = False
    ) -> Optional[Any]:
        resp = self.request("GET", endpoint, params=params)
        if resp.status_code == 200:
            return resp.json()
        if resp.status_code == 404 and allow_404:
            return None
        raise GitHubAPIError(f"GET {endpoint} -> HTTP {resp.status_code}: {resp.text[:200]}")

    def get_text(
        self,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        accept: str = "application/vnd.github.raw+json",
    ) -> Optional[str]:
        """Returns None only on 404. Any other non-200 raises."""
        resp = self.request("GET", endpoint, params=params, headers={"Accept": accept})
        if resp.status_code == 200:
            if len(resp.content) > MAX_FILE_BYTES:
                raise GitHubAPIError(f"{endpoint}: response larger than {MAX_FILE_BYTES} bytes")
            return resp.content.decode("utf-8", errors="replace")
        if resp.status_code == 404:
            return None
        raise GitHubAPIError(f"GET {endpoint} -> HTTP {resp.status_code}: {resp.text[:200]}")

    def paginate(
        self, endpoint: str, params: Optional[Dict[str, Any]] = None
    ) -> Generator[Dict[str, Any], None, None]:
        """Yields all items. Raises on any failure (never silently truncates)."""
        url = endpoint if endpoint.startswith("http") else f"{self.BASE_URL}/{endpoint.lstrip('/')}"
        req_params: Optional[Dict[str, Any]] = dict(params or {})
        req_params.setdefault("per_page", 100)  # type: ignore[union-attr]

        while url:
            resp = self.request("GET", url, params=req_params)
            if resp.status_code != 200:
                raise GitHubAPIError(f"Pagination failed on {url}: HTTP {resp.status_code}")
            data = resp.json()
            if isinstance(data, list):
                yield from data
            elif isinstance(data, dict):
                for key in ("check_runs", "items", "statuses"):
                    if key in data:
                        yield from data[key]
                        break
                else:
                    yield data
                    return
            else:
                return

            url = ""
            req_params = None  # next URL already carries its query
            for part in (resp.headers.get("link") or "").split(","):
                m = re.match(r'<([^>]+)>;\s*rel="([^"]+)"', part.strip())
                if m and m.group(2) == "next":
                    url = m.group(1)
                    break

    def close(self) -> None:
        self._client.close()


# =====================================================================
# Version utilities
# =====================================================================

_PIN_RE = re.compile(r"^===?\s*([A-Za-z0-9][A-Za-z0-9.!+_\-]*)$")


def pin_of(spec: str) -> Optional[str]:
    """Returns the version if `spec` is an exact pin (==x / ===x), else None."""
    m = _PIN_RE.match(spec.strip())
    return m.group(1) if m else None


def classify_bump(old: str, new: str) -> Dict[str, Any]:
    """Direction-aware bump classification with convention flags."""
    try:
        vo, vn = Version(old), Version(new)
    except InvalidVersion:
        return {
            "bump_type": "unknown",
            "is_valid_pep440": False,
            "is_calver": False,
            "is_zero_major": False,
            "involves_prerelease": False,
        }
    flags = {
        "is_valid_pep440": True,
        "is_calver": (vo.release[0] >= 2000 or vn.release[0] >= 2000),
        "is_zero_major": vo.release[0] == 0,
        "involves_prerelease": vo.is_prerelease or vn.is_prerelease,
    }
    if vn == vo:
        return {"bump_type": "same", **flags}
    if vn < vo:
        return {"bump_type": "downgrade", **flags}

    width = max(len(vo.release), len(vn.release), 3)
    ro = list(vo.release) + [0] * (width - len(vo.release))
    rn = list(vn.release) + [0] * (width - len(vn.release))
    if vo.epoch != vn.epoch:
        return {"bump_type": "major", **flags}
    for idx in range(width):
        if ro[idx] != rn[idx]:
            return {"bump_type": ("major", "minor")[idx] if idx < 2 else "patch", **flags}
    return {"bump_type": "prerelease_or_post", **flags}


# Tightly-coupled packages that legitimately change together.
KNOWN_COMPANION_FAMILIES: List[Set[str]] = [
    {"pydantic", "pydantic-core"},
]


def are_companion_packages(packages: Set[str]) -> bool:
    """True if exactly one package, or all belong to one known companion family."""
    canon = {canonicalize_name(p) for p in packages}
    if not canon:
        return False
    if len(canon) == 1:
        return True
    return any(canon.issubset(family) for family in KNOWN_COMPANION_FAMILIES)


# =====================================================================
# Manifest / lockfile parsing (state-based, not diff-based)
# =====================================================================


@dataclass
class ParsedFile:
    # canonical name -> set of spec strings (direct manifests) or version strings (lockfiles)
    specs: Dict[str, Set[str]] = field(default_factory=dict)
    raw_names: Dict[str, str] = field(default_factory=dict)
    unparsed: Set[str] = field(default_factory=set)

    def add(self, raw_name: str, spec: str) -> None:
        canon = canonicalize_name(raw_name)
        self.raw_names.setdefault(canon, raw_name)
        self.specs.setdefault(canon, set()).add(spec)


@dataclass
class PkgChange:
    removed: Set[str] = field(default_factory=set)
    added: Set[str] = field(default_factory=set)
    files: Set[str] = field(default_factory=set)


Reader = Callable[[str, str], Optional[str]]  # (path, "before"|"after") -> text or None


def _req_to_spec(req: Requirement) -> str:
    if req.url:
        return f"@{req.url}"
    s = str(req.specifier)
    return s if s else "<any>"


def _add_requirement_string(parsed: ParsedFile, text: str) -> None:
    text = text.strip()
    if not text:
        return
    try:
        req = Requirement(text)
    except InvalidRequirement:
        parsed.unparsed.add(text)
        return
    parsed.add(req.name, _req_to_spec(req))


def _clean_req_line(raw: str) -> str:
    line = raw.strip()
    if line.endswith("\\"):
        line = line[:-1].strip()
    line = re.sub(r"\s+#.*$", "", line)
    m = re.search(r"\s--[A-Za-z]", line)  # inline options such as --hash=...
    if m:
        line = line[: m.start()].strip()
    return line


def parse_requirements_text(text: str) -> ParsedFile:
    parsed = ParsedFile()
    for raw in text.splitlines():
        line = _clean_req_line(raw)
        if not line or line.startswith("#"):
            continue
        if line.startswith("-"):
            if line.startswith(("-e ", "--editable")):
                parsed.unparsed.add(line)  # editable installs cannot be resolved here
            continue  # -r / -c / --index-url / --hash continuation lines
        _add_requirement_string(parsed, line)
    return parsed


def _poetry_spec(val: Any) -> str:
    if isinstance(val, str):
        v = val.strip()
        if re.fullmatch(r"[0-9][A-Za-z0-9.!+_\-]*", v):
            return f"=={v}"  # Poetry: a bare version is an exact pin
        return f"poetry:{v}"
    if isinstance(val, dict):
        if any(k in val for k in ("git", "path", "url")):
            return "@source"
        if "version" in val:
            return _poetry_spec(val["version"])
        return "poetry:<no-version>"
    if isinstance(val, list):
        return "poetry:<multi>"
    return "poetry:<unknown>"


def _add_poetry_table(parsed: ParsedFile, table: Any) -> None:
    if not isinstance(table, dict):
        return
    for name, val in table.items():
        if name.lower() == "python":
            continue
        parsed.add(name, _poetry_spec(val))


def parse_pyproject(text: str) -> ParsedFile:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as err:
        raise ParseError(f"invalid TOML: {err}") from err
    parsed = ParsedFile()

    def add_list(items: Any) -> None:
        if isinstance(items, list):
            for item in items:
                if isinstance(item, str):
                    _add_requirement_string(parsed, item)

    project = data.get("project", {}) or {}
    add_list(project.get("dependencies"))
    for group in (project.get("optional-dependencies") or {}).values():
        add_list(group)
    for group in (data.get("dependency-groups") or {}).values():
        add_list(group)

    tool = data.get("tool", {}) or {}
    add_list((tool.get("uv") or {}).get("dev-dependencies"))
    for group in ((tool.get("pdm") or {}).get("dev-dependencies") or {}).values():
        add_list(group)
    poetry = tool.get("poetry", {}) or {}
    _add_poetry_table(parsed, poetry.get("dependencies"))
    _add_poetry_table(parsed, poetry.get("dev-dependencies"))
    for grp in (poetry.get("group") or {}).values():
        _add_poetry_table(parsed, (grp or {}).get("dependencies"))
    return parsed


def parse_setup_cfg(text: str) -> ParsedFile:
    cp = configparser.ConfigParser(interpolation=None, strict=False)
    try:
        cp.read_string(text)
    except configparser.Error as err:
        raise ParseError(f"invalid setup.cfg: {err}") from err
    parsed = ParsedFile()

    def add_block(block: str) -> None:
        for line in block.splitlines():
            line = _clean_req_line(line)
            if line and not line.startswith("#"):
                _add_requirement_string(parsed, line)

    if cp.has_section("options"):
        for key in ("install_requires", "setup_requires", "tests_require"):
            if cp.has_option("options", key):
                add_block(cp.get("options", key))
    for section in cp.sections():
        if section.startswith("options.extras_require"):
            for key in cp.options(section):
                add_block(cp.get(section, key))
    return parsed


def _pipfile_spec(val: Any) -> str:
    if isinstance(val, str):
        v = val.strip()
        if v == "*":
            return "<any>"
        if v.startswith("=="):
            return v
        return f"pipfile:{v}"
    if isinstance(val, dict):
        if any(k in val for k in ("git", "path", "file", "editable")):
            return "@source"
        if "version" in val:
            return _pipfile_spec(val["version"])
        return "<any>"
    return "pipfile:<unknown>"


def parse_pipfile(text: str) -> ParsedFile:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as err:
        raise ParseError(f"invalid Pipfile: {err}") from err
    parsed = ParsedFile()
    for section in ("packages", "dev-packages"):
        for name, val in (data.get(section) or {}).items():
            parsed.add(name, _pipfile_spec(val))
    return parsed


def parse_toml_lock(text: str) -> ParsedFile:
    """poetry.lock / uv.lock / pdm.lock: [[package]] name + version."""
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as err:
        raise ParseError(f"invalid lockfile TOML: {err}") from err
    pkgs = data.get("package", [])
    if not isinstance(pkgs, list):
        raise ParseError("lockfile has no [[package]] array")
    parsed = ParsedFile()
    for pkg in pkgs:
        name, ver = pkg.get("name"), pkg.get("version")
        if not name or ver is None:
            continue
        src = pkg.get("source")
        if isinstance(src, dict) and any(k in src for k in ("editable", "virtual", "directory")):
            continue  # the project itself
        parsed.add(name, str(ver))
    return parsed


def parse_pipfile_lock(text: str) -> ParsedFile:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as err:
        raise ParseError(f"invalid Pipfile.lock JSON: {err}") from err
    parsed = ParsedFile()
    for section in ("default", "develop"):
        for name, val in (data.get(section) or {}).items():
            ver = (val or {}).get("version", "")
            if isinstance(ver, str) and ver.startswith("=="):
                parsed.add(name, ver[2:])
    return parsed


def parse_requirements_lock(text: str) -> ParsedFile:
    base = parse_requirements_text(text)
    parsed = ParsedFile(raw_names=dict(base.raw_names), unparsed=set(base.unparsed))
    for name, specs in base.specs.items():
        for spec in specs:
            ver = pin_of(spec)
            if ver:
                parsed.specs.setdefault(name, set()).add(ver)
            else:
                parsed.unparsed.add(f"{name}{spec}")
    return parsed


_PARSERS: Dict[str, Callable[[str], ParsedFile]] = {
    "requirements": parse_requirements_text,
    "pyproject": parse_pyproject,
    "setup_cfg": parse_setup_cfg,
    "pipfile": parse_pipfile,
    "poetry_lock": parse_toml_lock,
    "uv_lock": parse_toml_lock,
    "pdm_lock": parse_toml_lock,
    "pipfile_lock": parse_pipfile_lock,
    "requirements_lock": parse_requirements_lock,
}


def _diff_maps(
    before: Dict[str, Set[str]], after: Dict[str, Set[str]]
) -> Dict[str, Tuple[Set[str], Set[str]]]:
    out: Dict[str, Tuple[Set[str], Set[str]]] = {}
    for name in set(before) | set(after):
        b, a = before.get(name, set()), after.get(name, set())
        if b != a:
            out[name] = (b - a, a - b)
    return out


class ManifestDiffParser:
    """Derives dependency changes by comparing parsed file states at two commits."""

    DIRECT_NAME_PATTERNS = [
        re.compile(r"^[\w.\-]*requirements[\w.\-]*\.(txt|in)$", re.I),
        re.compile(r"^constraints[\w.\-]*\.(txt|in)$", re.I),
        re.compile(r"^pyproject\.toml$", re.I),
        re.compile(r"^setup\.cfg$", re.I),
        re.compile(r"^setup\.py$", re.I),
        re.compile(r"^Pipfile$", re.I),
    ]
    DIRECT_DIR_PATTERN = re.compile(r"(^|/)requirements/[^/]+\.(txt|in)$", re.I)
    LOCKFILE_PATTERNS = [
        re.compile(r"^poetry\.lock$", re.I),
        re.compile(r"^uv\.lock$", re.I),
        re.compile(r"^Pipfile\.lock$", re.I),
        re.compile(r"^pdm\.lock$", re.I),
        re.compile(r"^[\w.\-]*requirements[\w.\-]*\.lock$", re.I),
    ]
    DOC_OR_CONFIG_PATTERNS = [
        re.compile(r"^\.github/", re.I),
        re.compile(r"\.(md|rst|txt|png|jpg|svg|gitignore|editorconfig)$", re.I),
    ]
    # Manifests under these directories never affect the test environment.
    AUX_DIRS = {
        "docs", "doc", "documentation", "examples", "example",
        "samples", "benchmarks", "benchmark", "tutorials", "notebooks",
    }

    @classmethod
    def categorize_filename(cls, path: str) -> str:
        base = os.path.basename(path)
        is_direct = any(p.search(base) for p in cls.DIRECT_NAME_PATTERNS) or bool(
            cls.DIRECT_DIR_PATTERN.search(path)
        )
        is_lock = any(p.search(base) for p in cls.LOCKFILE_PATTERNS)
        if is_direct or is_lock:
            parents = {p.lower() for p in path.split("/")[:-1]}
            if parents & cls.AUX_DIRS:
                return "aux_manifest"
            return "lockfile" if is_lock else "direct_manifest"
        if any(p.search(path) for p in cls.DOC_OR_CONFIG_PATTERNS):
            return "doc_or_config"
        return "non_manifest_code"

    @staticmethod
    def file_kind(path: str) -> str:
        base = os.path.basename(path).lower()
        mapping = {
            "pyproject.toml": "pyproject",
            "setup.cfg": "setup_cfg",
            "setup.py": "setup_py",
            "pipfile": "pipfile",
            "poetry.lock": "poetry_lock",
            "uv.lock": "uv_lock",
            "pdm.lock": "pdm_lock",
            "pipfile.lock": "pipfile_lock",
        }
        if base in mapping:
            return mapping[base]
        return "requirements_lock" if base.endswith(".lock") else "requirements"

    @classmethod
    def _load(cls, kind: str, path: str, side: str, status: str, reader: Reader) -> ParsedFile:
        if (side == "before" and status == "added") or (side == "after" and status == "removed"):
            return ParsedFile()
        if kind == "setup_py":
            raise ParseError("setup.py is not statically parsed")
        text = reader(path, side)
        if text is None:
            raise ParseError(f"{path}@{side} unreadable (missing or inaccessible)")
        return _PARSERS[kind](text)

    @classmethod
    def analyze(
        cls, files: List[Dict[str, Any]], reader: Reader
    ) -> Tuple[ManifestAnalysis, List[VersionBump]]:
        direct_files: List[str] = []
        lockfiles: List[str] = []
        aux_files: List[str] = []
        non_manifest: List[str] = []
        unparseable: List[str] = []
        notes: List[str] = []
        rejections: List[str] = []
        inconclusive: List[str] = []
        direct_changes: Dict[str, PkgChange] = {}
        lock_changes: Dict[str, PkgChange] = {}
        raw_names: Dict[str, str] = {}
        lock_unparseable = False

        for f in files:
            fn = f.get("filename", "")
            status = f.get("status", "modified")
            prev = f.get("previous_filename") or fn
            cat = cls.categorize_filename(fn)
            if cat == "non_manifest_code":
                non_manifest.append(fn)
                continue
            if cat == "aux_manifest":
                aux_files.append(fn)
                continue
            if cat == "doc_or_config":
                continue

            is_lock = cat == "lockfile"
            (lockfiles if is_lock else direct_files).append(fn)
            kind = cls.file_kind(fn)
            try:
                before = cls._load(kind, prev, "before", status, reader)
                after = cls._load(kind, fn, "after", status, reader)
            except ParseError as err:
                unparseable.append(fn)
                notes.append(f"{fn}: {err}")
                lock_unparseable = lock_unparseable or is_lock
                continue
            if before.unparsed != after.unparsed:
                unparseable.append(fn)
                changed = sorted(before.unparsed ^ after.unparsed)[:3]
                notes.append(f"{fn}: changed entries could not be parsed: {changed}")
                lock_unparseable = lock_unparseable or is_lock
                continue

            raw_names.update(before.raw_names)
            raw_names.update(after.raw_names)
            bucket = lock_changes if is_lock else direct_changes
            for name, (rem, add) in _diff_maps(before.specs, after.specs).items():
                ch = bucket.setdefault(name, PkgChange())
                ch.removed |= rem
                ch.added |= add
                ch.files.add(fn)

        if non_manifest:
            rejections.append(
                f"EXC-06: PR includes bundled non-manifest files: {non_manifest[:3]}"
            )
        if unparseable:
            inconclusive.append("INCONCLUSIVE_UNPARSEABLE_MANIFEST")

        direct_names, lock_names = set(direct_changes), set(lock_changes)
        if not (direct_names | lock_names) and not unparseable:
            rejections.append("EXC-01: no dependency version change found in manifests/lockfiles")

        targets = sorted(direct_names if direct_names else lock_names)
        single = are_companion_packages(set(targets))
        multi_direct = len(direct_names) > 1 and not are_companion_packages(direct_names)
        if multi_direct:
            rejections.append(
                f"EXC-02: PR changes {len(direct_names)} direct dependencies {sorted(direct_names)[:3]}; "
                "exactly one is required"
            )

        # ---- lockfile confound status ----
        if not lockfiles:
            lock_status, risk = "NO_LOCKFILE", "LOW"
        elif lock_unparseable:
            lock_status, risk = "UNPARSEABLE_LOCKFILE", "UNKNOWN"
            inconclusive.append("INCONCLUSIVE_LOCKFILE_UNPARSEABLE")
        else:
            extra = lock_names - set(targets)
            lock_only_multi = (not direct_names) and not single
            if lock_only_multi or (extra and not are_companion_packages(lock_names | set(targets))):
                lock_status, risk = "UNRESOLVED_LOCKFILE_CHANGE", "HIGH"
                if not multi_direct:
                    inconclusive.append("INCONCLUSIVE_LOCKFILE_CHURN")
                notes.append(
                    f"Lockfile changes beyond target: {sorted(lock_names - set(targets))[:5] or sorted(lock_names)[:5]}"
                )
            elif extra:
                lock_status, risk = "COMPANION_ISOLATED", "LOW"
            else:
                lock_status, risk = "CONFIRMED_ISOLATED", "LOW"

        # ---- derive bumps ----
        bumps: List[VersionBump] = []
        if targets and single and not multi_direct:
            for name in targets:
                bump = cls._derive_bump(
                    name, direct_changes, lock_changes, raw_names, rejections, inconclusive, notes
                )
                if bump:
                    bumps.append(bump)

        analysis = ManifestAnalysis(
            direct_manifest_files=direct_files,
            lockfile_files=lockfiles,
            non_manifest_files=non_manifest,
            canonical_packages_modified=sorted(direct_names | lock_names),
            exactly_one_dependency_updated=bool(targets) and single,
            lockfile_status=lock_status,
            transitive_confound_risk=risk,
            notes=notes,
            aux_manifest_files=aux_files,
            unparseable_files=unparseable,
            rejections=rejections,
            inconclusive_codes=list(dict.fromkeys(inconclusive)),
        )
        return analysis, bumps

    @staticmethod
    def _derive_bump(
        name: str,
        direct_changes: Dict[str, PkgChange],
        lock_changes: Dict[str, PkgChange],
        raw_names: Dict[str, str],
        rejections: List[str],
        inconclusive: List[str],
        notes: List[str],
    ) -> Optional[VersionBump]:
        use_lock = name in lock_changes
        change = lock_changes[name] if use_lock else direct_changes[name]

        if use_lock:
            removed, added, source = set(change.removed), set(change.added), "lockfile"
        else:
            specs = change.removed | change.added
            if any(pin_of(s) is None for s in specs):
                inconclusive.append("INCONCLUSIVE_UNPINNED_SPEC")
                notes.append(
                    f"{name}: non-pinned specifier(s) {sorted(specs)[:4]} and no lockfile; resolved version unknown"
                )
                return None
            removed = {v for v in (pin_of(s) for s in change.removed) if v}
            added = {v for v in (pin_of(s) for s in change.added) if v}
            source = "direct_pin"

        if not removed or not added:
            rejections.append(f"EXC-08: dependency '{name}' was added or removed, not upgraded")
            return None
        if len(removed) != 1 or len(added) != 1:
            inconclusive.append("INCONCLUSIVE_AMBIGUOUS_VERSIONS")
            notes.append(f"{name}: ambiguous versions removed={sorted(removed)} added={sorted(added)}")
            return None

        old, new = next(iter(removed)), next(iter(added))
        if use_lock and name in direct_changes:
            direct_new = {v for v in (pin_of(s) for s in direct_changes[name].added) if v}
            if direct_new and direct_new != {new}:
                inconclusive.append("INCONCLUSIVE_PIN_LOCK_MISMATCH")
                notes.append(f"{name}: direct pin {sorted(direct_new)} != locked version {new}")
                return None

        info = classify_bump(old, new)
        if info["bump_type"] in ("downgrade", "same"):
            rejections.append(f"EXC-10: '{name}' {old} -> {new} is not an upgrade ({info['bump_type']})")
            return None
        if info["bump_type"] == "unknown":
            rejections.append(f"EXC-11: '{name}' has non-PEP 440 version(s): {old} -> {new}")
            return None

        return VersionBump(
            package_name=name,
            raw_package_name=raw_names.get(name, name),
            old_version=old,
            new_version=new,
            bump_type=info["bump_type"],
            is_valid_pep440=True,
            is_calver=info["is_calver"],
            is_zero_major=info["is_zero_major"],
            involves_prerelease=info["involves_prerelease"],
            resolution_source=source,
            manifest_source=sorted(change.files)[0] if change.files else "unknown",
        )


# =====================================================================
# GitHub-backed file reader, tests detection, CI evidence
# =====================================================================


class GitHubFileReader:
    """Reads file text at the merge-base ("before") and head ("after") commits."""

    def __init__(
        self,
        client: GitHubClient,
        owner: str,
        repo: str,
        before_sha: str,
        after_sha: str,
        head_repo_full_name: Optional[str] = None,
    ):
        self.client, self.owner, self.repo = client, owner, repo
        self.before_sha, self.after_sha = before_sha, after_sha
        self.head_repo = head_repo_full_name

    def _fetch(self, full_name: str, path: str, sha: str) -> Optional[str]:
        endpoint = f"repos/{full_name}/contents/{quote(path)}"
        return self.client.get_text(endpoint, params={"ref": sha})

    def __call__(self, path: str, side: str) -> Optional[str]:
        sha = self.before_sha if side == "before" else self.after_sha
        text = self._fetch(f"{self.owner}/{self.repo}", path, sha)
        if text is None and side == "after" and self.head_repo:
            if self.head_repo.lower() != f"{self.owner}/{self.repo}".lower():
                text = self._fetch(self.head_repo, path, sha)
        return text


TEST_PATH_RE = re.compile(r"(^|/)(tests?|testing)/.+\.py$|(^|/)test_[^/]+\.py$|_test\.py$")
TEST_CHECK_RE = re.compile(r"(test|pytest|tox|nox|unittest)", re.I)
_FAIL_CONCLUSIONS = ("failure", "timed_out", "action_required", "cancelled")


def detect_tests(paths: List[str], truncated: bool) -> TestEvidence:
    count = sum(1 for p in paths if TEST_PATH_RE.search(p))
    return TestEvidence(tests_present=count > 0, test_file_count=count, tree_truncated=truncated)


def fetch_tree_paths(client: GitHubClient, owner: str, repo: str, sha: str) -> Tuple[List[str], bool]:
    data = client.get_json(f"repos/{owner}/{repo}/git/trees/{sha}", params={"recursive": "1"})
    if not isinstance(data, dict):
        raise GitHubAPIError(f"Tree for {owner}/{repo}@{sha} unavailable")
    paths = [t["path"] for t in data.get("tree", []) if t.get("type") == "blob"]
    return paths, bool(data.get("truncated", False))


def fetch_ci_for_commit(
    client: GitHubClient, owner: str, repo: str, sha: str
) -> Tuple[List[Dict[str, Any]], str]:
    """Check runs + combined statuses. Raises on API failure; 0 checks => UNKNOWN."""
    if not sha:
        return [], "UNKNOWN"
    checks: List[Dict[str, Any]] = []
    for c in client.paginate(f"repos/{owner}/{repo}/commits/{sha}/check-runs"):
        checks.append(
            {
                "name": c.get("name", "unnamed_check"),
                "status": c.get("status"),
                "conclusion": c.get("conclusion"),
            }
        )
    status_data = client.get_json(
        f"repos/{owner}/{repo}/commits/{sha}/status", params={"per_page": 100}, allow_404=True
    )
    for s in (status_data or {}).get("statuses", []):
        state = s.get("state")
        conclusion = "failure" if state in ("error", "failure") else state
        checks.append({"name": s.get("context", "unnamed_status"), "status": "completed", "conclusion": conclusion})

    if not checks:
        return [], "UNKNOWN"
    if any(c.get("conclusion") in _FAIL_CONCLUSIONS for c in checks):
        return checks, "FAILURE"
    if all(c.get("conclusion") in ("success", "neutral", "skipped") for c in checks):
        return checks, "SUCCESS"
    return checks, "UNKNOWN"


# =====================================================================
# Candidate evaluation
# =====================================================================

_PR_URL_RE = re.compile(
    r"^https?://(?:www\.)?github\.com/([^/\s]+)/([^/\s]+)/pull/(\d+)(?:[/?#].*)?$", re.I
)
_API_PR_URL_RE = re.compile(
    r"^https?://api\.github\.com/repos/([^/\s]+)/([^/\s]+)/pulls/(\d+)(?:[/?#].*)?$", re.I
)


def parse_pr_url(url: str) -> Optional[Tuple[str, str, int]]:
    for pat in (_PR_URL_RE, _API_PR_URL_RE):
        m = pat.match(url.strip())
        if m:
            return m.group(1), m.group(2), int(m.group(3))
    return None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _short_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:10]


def make_simple_record(
    case_id: str,
    status: str,
    reasons: List[str],
    repository: Optional[Dict[str, Any]] = None,
    pull_request: Optional[Dict[str, Any]] = None,
    error: Optional[str] = None,
) -> CandidateRecord:
    return CandidateRecord(
        case_id=case_id,
        collection_status=status,
        rejection_reasons=reasons if status == "REJECTED" else [],
        inconclusive_reasons=[],
        collected_at=_now(),
        repository=repository or {},
        pull_request=pull_request or {},
        dependency_bump=None,
        companion_bumps=[],
        manifest_analysis={},
        ci_evidence={},
        test_evidence={},
        validation_checklist={},
        error=error,
    )


def evaluate_candidate_pr(
    client: GitHubClient,
    pr_url: str,
    require_merged: bool = False,
    min_python_share: float = MIN_PYTHON_SHARE_DEFAULT,
) -> CandidateRecord:
    """Raises GitHubAPIError on infrastructure failure (caller records status=ERROR)."""
    parsed_url = parse_pr_url(pr_url)
    if not parsed_url:
        return make_simple_record(
            f"INVALID_URL-{_short_hash(pr_url)}", "REJECTED", ["Malformed GitHub PR URL."],
            repository={"url": pr_url}, pull_request={"url": pr_url},
        )
    owner, repo, number = parsed_url
    canonical_url = f"https://github.com/{owner}/{repo}/pull/{number}"

    pr = client.get_json(f"repos/{owner}/{repo}/pulls/{number}", allow_404=True)
    if not pr:
        return make_simple_record(
            f"TIER-B-{owner}-{repo}-{number}-NOTFOUND", "REJECTED",
            [f"PR {owner}/{repo}#{number} not found (HTTP 404)."],
            repository={"owner": owner, "name": repo}, pull_request={"url": canonical_url, "number": number},
        )

    api_base_sha = (pr.get("base") or {}).get("sha", "")
    head_sha = (pr.get("head") or {}).get("sha", "")
    head_repo_full = ((pr.get("head") or {}).get("repo") or {}).get("full_name")
    case_id = f"TIER-B-{owner}-{repo}-{number}-{head_sha[:8]}"

    repo_details = client.get_json(f"repos/{owner}/{repo}") or {}
    languages = client.get_json(f"repos/{owner}/{repo}/languages") or {}
    total_bytes = sum(languages.values())
    python_share = (languages.get("Python", 0) / total_bytes) if total_bytes else 0.0

    repository = {
        "full_name": f"{owner}/{repo}",
        "language": repo_details.get("language"),
        "languages_breakdown": languages,
        "python_share": round(python_share, 4),
        "stars": repo_details.get("stargazers_count", 0),
        "html_url": repo_details.get("html_url", ""),
    }
    is_merged = bool(pr.get("merged", False))
    pr_state = pr.get("state", "closed")
    pull_request = {
        "url": canonical_url,
        "number": number,
        "title": pr.get("title", ""),
        "state": pr_state,
        "is_merged": is_merged,
        "merge_status": "MERGED" if is_merged else ("UNMERGED_CLOSED" if pr_state == "closed" else "OPEN"),
        "created_at": pr.get("created_at"),
        "closed_at": pr.get("closed_at"),
        "merged_at": pr.get("merged_at"),
        "base_ref": (pr.get("base") or {}).get("ref", ""),
        "api_base_sha": api_base_sha,
        "head_ref": (pr.get("head") or {}).get("ref", ""),
        "head_sha": head_sha,
    }

    if python_share < min_python_share:
        rec = make_simple_record(
            case_id, "REJECTED",
            [f"EXC-05: Python share {python_share:.1%} below minimum {min_python_share:.0%}."],
            repository=repository, pull_request=pull_request,
        )
        return rec

    # ---- merge-base (the true "before" commit) ----
    compare = client.get_json(f"repos/{owner}/{repo}/compare/{api_base_sha}...{head_sha}")
    merge_base_sha = ((compare or {}).get("merge_base_commit") or {}).get("sha", "")
    if not merge_base_sha:
        raise GitHubAPIError(f"No merge-base for {owner}/{repo}#{number}")
    pull_request["merge_base_sha"] = merge_base_sha

    # ---- changed files ----
    files = list(client.paginate(f"repos/{owner}/{repo}/pulls/{number}/files"))
    inconclusive_extra: List[str] = []
    if len(files) >= MAX_PR_FILES:
        inconclusive_extra.append("INCONCLUSIVE_FILE_LIST_TRUNCATED")

    reader = GitHubFileReader(client, owner, repo, merge_base_sha, head_sha, head_repo_full)
    analysis, bumps = ManifestDiffParser.analyze(files, reader)

    # ---- tests present at the "before" commit? ----
    tree_paths, truncated = fetch_tree_paths(client, owner, repo, merge_base_sha)
    tests = detect_tests(tree_paths, truncated)
    if not tests.tests_present:
        inconclusive_extra.append("INCONCLUSIVE_TESTS_UNKNOWN" if truncated else "INCONCLUSIVE_NO_TESTS")

    # ---- observational CI at merge-base and head ----
    base_checks, base_ci = fetch_ci_for_commit(client, owner, repo, merge_base_sha)
    head_checks, head_ci = fetch_ci_for_commit(client, owner, repo, head_sha)
    ci = CIEvidence(
        api_base_sha=api_base_sha,
        merge_base_sha=merge_base_sha,
        head_sha=head_sha,
        base_ci_status=base_ci,
        head_ci_status=head_ci,
        base_checks_count=len(base_checks),
        head_checks_count=len(head_checks),
        base_failed_checks=[c["name"] for c in base_checks if c.get("conclusion") in _FAIL_CONCLUSIONS],
        head_failed_checks=[c["name"] for c in head_checks if c.get("conclusion") in _FAIL_CONCLUSIONS],
        base_test_like_checks=[c["name"] for c in base_checks if TEST_CHECK_RE.search(c["name"])],
    )
    if base_ci == "FAILURE":
        inconclusive_extra.append("INCONCLUSIVE_BASE_CI_FAILED")
    elif base_ci == "UNKNOWN":
        inconclusive_extra.append("INCONCLUSIVE_NO_BASELINE_CI")

    # ---- rejections / inconclusive ----
    rejections = list(analysis.rejections)
    if require_merged and not is_merged:
        rejections.append("EXC-09: PR not merged (--require-merged set).")
    if not bumps and not rejections and not analysis.inconclusive_codes:
        analysis.inconclusive_codes.append("INCONCLUSIVE_NO_BUMP_DERIVED")
    inconclusive = list(dict.fromkeys(analysis.inconclusive_codes + inconclusive_extra))

    if rejections:
        status = "REJECTED"
    elif inconclusive:
        status = "INCONCLUSIVE"
    else:
        status = "ACCEPTED_CANDIDATE"

    checklist = ValidationChecklist(
        python_repo_verified=True,
        single_dependency_verified=analysis.exactly_one_dependency_updated,
        versions_resolved=bool(bumps),
        no_non_manifest_code_edits=not analysis.non_manifest_files,
        commit_shas_captured=bool(merge_base_sha and head_sha),
        lockfile_confound_free=analysis.lockfile_status
        in ("NO_LOCKFILE", "CONFIRMED_ISOLATED", "COMPANION_ISOLATED"),
        tests_present=tests.tests_present,
        base_ci_status=base_ci,
        pr_merged=is_merged,
        ready_for_differential_replay=(status == "ACCEPTED_CANDIDATE"),
    )

    return CandidateRecord(
        case_id=case_id,
        collection_status=status,
        rejection_reasons=rejections,
        inconclusive_reasons=inconclusive,
        inconclusive_reason=inconclusive[0] if inconclusive and status == "INCONCLUSIVE" else None,
        collected_at=_now(),
        repository=repository,
        pull_request=pull_request,
        dependency_bump=asdict(bumps[0]) if bumps else None,
        companion_bumps=[asdict(b) for b in bumps[1:]],
        manifest_analysis=asdict(analysis),
        ci_evidence=asdict(ci),
        test_evidence=asdict(tests),
        validation_checklist=asdict(checklist),
    )


def model_visible_view(rec: Dict[str, Any]) -> Dict[str, Any]:
    """Whitelist of fields that may reach the agent under evaluation.

    Deliberately excludes: PR title, merge status/timestamps, CI evidence, labels.
    """
    bump = rec.get("dependency_bump") or {}
    pr = rec.get("pull_request", {})
    return {
        "case_id": rec["case_id"],
        "repository": rec.get("repository", {}).get("full_name"),
        "pr_url": pr.get("url"),
        "before_sha": pr.get("merge_base_sha"),
        "after_sha": pr.get("head_sha"),
        "package": bump.get("package_name"),
        "old_version": bump.get("old_version"),
        "new_version": bump.get("new_version"),
        "bump_type": bump.get("bump_type"),
        "companion_packages": [
            {"package": b["package_name"], "old": b["old_version"], "new": b["new_version"]}
            for b in rec.get("companion_bumps", [])
        ],
    }


# =====================================================================
# Storage: write-once batches
# =====================================================================


class DatasetStorage:
    def __init__(self, bucket_name: str, firestore_project: str):
        self.bucket_name = bucket_name
        self.storage_client = None
        self.firestore_client = None
        if bucket_name:
            try:
                from google.cloud import storage

                self.storage_client = storage.Client()
            except Exception as err:
                logger.error("Cloud Storage init failed: %s", err)
        if firestore_project:
            try:
                from google.cloud import firestore

                self.firestore_client = firestore.Client(project=firestore_project)
            except Exception as err:
                logger.error("Firestore init failed: %s", err)

    def write_immutable_batch(
        self, execution_id: str, records: List[CandidateRecord], local_output_path: str
    ) -> str:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        batch_name = f"batch_{execution_id}_{ts}.jsonl"
        view_name = f"modelview_{execution_id}_{ts}.jsonl"
        manifest_name = f"manifest_{execution_id}_{ts}.json"

        content = "".join(json.dumps(asdict(r), sort_keys=True) + "\n" for r in records)
        view_content = "".join(
            json.dumps(model_visible_view(asdict(r)), sort_keys=True) + "\n"
            for r in records
            if r.collection_status == "ACCEPTED_CANDIDATE"
        )

        os.makedirs(local_output_path, exist_ok=True)
        local_file = os.path.join(local_output_path, batch_name)
        for name, text in ((batch_name, content), (view_name, view_content)):
            path = os.path.join(local_output_path, name)
            if os.path.exists(path):
                raise FileExistsError(f"Refusing to overwrite {path}")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
        logger.info("Saved %s (%d records)", local_file, len(records))

        if self.storage_client and self.bucket_name:
            bucket = self.storage_client.bucket(self.bucket_name)
            counts = {s: sum(1 for r in records if r.collection_status == s)
                      for s in ("ACCEPTED_CANDIDATE", "REJECTED", "INCONCLUSIVE", "ERROR")}
            manifest = {
                "execution_id": execution_id,
                "schema_version": SCHEMA_VERSION,
                "batch_file": f"gs://{self.bucket_name}/{BATCH_OUTPUT_DIR}/{batch_name}",
                "timestamp": _now(),
                "total_evaluated": len(records),
                "counts": counts,
                "sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
            }
            # if_generation_match=0 => create-only; fails if the object already exists.
            bucket.blob(f"{BATCH_OUTPUT_DIR}/{batch_name}").upload_from_string(
                content, content_type="application/x-ndjson", if_generation_match=0
            )
            bucket.blob(f"{MANIFEST_OUTPUT_DIR}/{manifest_name}").upload_from_string(
                json.dumps(manifest, indent=2), content_type="application/json", if_generation_match=0
            )

        if self.firestore_client:
            from google.api_core.exceptions import AlreadyExists

            for rec in records:
                bump = rec.dependency_bump or {}
                doc = {
                    "case_id": rec.case_id,
                    "collection_status": rec.collection_status,
                    "pr_url": rec.pull_request.get("url"),
                    "package_name": bump.get("package_name"),
                    "old_version": bump.get("old_version"),
                    "new_version": bump.get("new_version"),
                    "rejection_reasons": rec.rejection_reasons,
                    "inconclusive_reasons": rec.inconclusive_reasons,
                    "collected_at": rec.collected_at,
                    "execution_id": execution_id,
                }
                doc_id = f"{rec.case_id}__{execution_id}".replace("/", "_")
                try:
                    self.firestore_client.collection("tier_b_candidates").document(doc_id).create(doc)
                except AlreadyExists:
                    logger.warning("Firestore doc %s already exists; not overwriting", doc_id)
        return local_file


# =====================================================================
# CLI
# =====================================================================


def parse_candidate_urls(raw_input: Any) -> List[str]:
    """Flatten strings / JSON / lists / dicts into canonical, de-duplicated PR URLs."""
    if not raw_input:
        return []

    def _flatten(item: Any):
        if isinstance(item, (list, tuple, set)):
            for sub in item:
                yield from _flatten(sub)
        elif isinstance(item, str):
            s = item.strip()
            if (s.startswith("[") and s.endswith("]")) or (s.startswith("{") and s.endswith("}")):
                try:
                    yield from _flatten(json.loads(s))
                    return
                except Exception:
                    pass
            for part in re.split(r"[\r\n,\s]+", s):
                p = part.strip().strip('"').strip("'")
                if p.startswith("http"):
                    yield p
        elif isinstance(item, dict):
            if "html_url" in item:
                yield str(item["html_url"]).strip()
            elif "url" in item:
                yield str(item["url"]).strip()
            else:
                for v in item.values():
                    yield from _flatten(v)

    seen: Set[str] = set()
    out: List[str] = []
    for url in _flatten(raw_input):
        parsed = parse_pr_url(url)
        if parsed:
            owner, repo, number = parsed
            key = f"{owner.lower()}/{repo.lower()}#{number}"
            canonical = f"https://github.com/{owner}/{repo}/pull/{number}"
        else:
            key, canonical = url, url  # kept so evaluation records it as INVALID_URL
        if key not in seen:
            seen.add(key)
            out.append(canonical)
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description="Tier B candidate collector (screening only; no labels)")
    ap.add_argument("--pr-urls", nargs="*", help="GitHub PR URLs")
    ap.add_argument("--urls-file", help="Text/JSON file with PR URLs")
    ap.add_argument("--execution-id", default=os.getenv("CLOUD_RUN_JOB_EXECUTION", f"manual_{int(time.time())}"))
    ap.add_argument("--output-dir", default="tier_b_output")
    ap.add_argument("--require-merged", action="store_true", help="Reject PRs that were not merged")
    ap.add_argument("--min-python-share", type=float, default=MIN_PYTHON_SHARE_DEFAULT)
    ap.add_argument("--max-rate-limit-wait", type=float, default=120.0)
    ap.add_argument("--max-consecutive-errors", type=int, default=5)
    args = ap.parse_args()

    raw: List[Any] = list(args.pr_urls or [])
    if args.urls_file and os.path.exists(args.urls_file):
        with open(args.urls_file, "r", encoding="utf-8") as fh:
            raw.append(fh.read())
    if os.getenv("CANDIDATE_PR_URLS"):
        raw.append(os.environ["CANDIDATE_PR_URLS"])
    urls = parse_candidate_urls(raw)
    if not urls:
        logger.error("No candidate PR URLs. Use --pr-urls, --urls-file or CANDIDATE_PR_URLS.")
        sys.exit(1)

    logger.info("Execution %s: %d candidates", args.execution_id, len(urls))
    client = GitHubClient(max_rate_limit_wait=args.max_rate_limit_wait)
    storage = DatasetStorage(GCS_BUCKET_NAME, FIRESTORE_PROJECT_ID)

    records: List[CandidateRecord] = []
    consecutive_errors = 0
    aborted = False
    try:
        for idx, url in enumerate(urls, 1):
            logger.info("[%d/%d] %s", idx, len(urls), url)
            try:
                rec = evaluate_candidate_pr(
                    client, url, require_merged=args.require_merged,
                    min_python_share=args.min_python_share,
                )
                consecutive_errors = 0
            except GitHubAPIError as err:
                logger.error("API error for %s: %s", url, err)
                rec = make_simple_record(
                    f"ERROR-{_short_hash(url + args.execution_id)}", "ERROR", [],
                    repository={"url": url}, pull_request={"url": url}, error=str(err),
                )
                consecutive_errors += 1
            except Exception as err:  # unexpected bug: surface it, never mask as REJECTED
                logger.exception("Unexpected error for %s", url)
                rec = make_simple_record(
                    f"ERROR-{_short_hash(url + args.execution_id)}", "ERROR", [],
                    repository={"url": url}, pull_request={"url": url},
                    error=f"{type(err).__name__}: {err}",
                )
                consecutive_errors += 1
            records.append(rec)
            logger.info("  -> %s %s", rec.collection_status,
                        rec.rejection_reasons or rec.inconclusive_reasons or rec.error or "")
            if consecutive_errors >= args.max_consecutive_errors:
                logger.error("Aborting after %d consecutive errors; rerun remaining URLs later.", consecutive_errors)
                aborted = True
                break

            if idx < len(urls):
                time.sleep(0.5)  # Courteous delay to avoid GitHub secondary rate limits

        if records:
            storage.write_immutable_batch(args.execution_id, records, args.output_dir)
        summary = {s: sum(1 for r in records if r.collection_status == s)
                   for s in ("ACCEPTED_CANDIDATE", "INCONCLUSIVE", "REJECTED", "ERROR")}
        logger.info("Done. Evaluated=%d %s", len(records), summary)
    finally:
        client.close()

    if aborted and not records:
        logger.error("Collector aborted without successfully recording any candidates.")
        sys.exit(2)


if __name__ == "__main__":
    main()