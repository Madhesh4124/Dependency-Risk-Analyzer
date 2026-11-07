"""Repository source code fetcher for AST scanning (Decision Checkpoint D-04: Option D)."""

import base64
import logging
from pathlib import Path
from typing import Dict, List, Optional
import httpx

from risk_agent.config import DEFAULT_CONFIG
from risk_agent.scanner.ast_scanner import EXCLUDED_DIRS

logger = logging.getLogger(__name__)


class RepoSourceFetcher:
    """Fetches repository source files for AST scanning adhering to D-04 Option D

    (Configurable with default Option A: GitHub API trees + blobs).
    """

    def __init__(
        self,
        github_token: Optional[str] = None,
        max_files: int = DEFAULT_CONFIG.scanner_max_file_count,
        max_file_bytes: int = DEFAULT_CONFIG.scanner_max_file_bytes,
        http_timeout: float = DEFAULT_CONFIG.http_timeout_seconds,
    ):
        self.github_token = github_token
        self.max_files = max_files
        self.max_file_bytes = max_file_bytes
        self.http_timeout = http_timeout

    def _get_headers(self) -> Dict[str, str]:
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "dependency-risk-agent/0.1.0",
        }
        if self.github_token:
            headers["Authorization"] = f"Bearer {self.github_token}"
        return headers

    async def fetch_sources_from_github(
        self,
        owner: str,
        repo: str,
        commit_sha: str,
    ) -> Dict[str, str]:
        """Fetches Python source files from GitHub using Git Trees API (Option A).

        Never clones the repository to disk; stores strictly in memory.
        """
        sources: Dict[str, str] = {}
        tree_url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/{commit_sha}?recursive=1"

        try:
            async with httpx.AsyncClient(timeout=self.http_timeout) as client:
                resp = await client.get(tree_url, headers=self._get_headers())
                if resp.status_code != 200:
                    logger.warning(
                        f"GitHub tree fetch failed for {owner}/{repo}@{commit_sha}: {resp.status_code}"
                    )
                    return sources

                data = resp.json()
                tree = data.get("tree", [])

                py_blobs = []
                for item in tree:
                    if item.get("type") != "blob":
                        continue
                    path = item.get("path", "")
                    if not path.endswith(".py"):
                        continue
                    parts = path.replace("\\", "/").split("/")
                    if any(p in EXCLUDED_DIRS for p in parts[:-1]):
                        continue
                    size = item.get("size", 0)
                    if size > self.max_file_bytes:
                        continue
                    py_blobs.append(item)
                    if len(py_blobs) >= self.max_files:
                        break

                for blob in py_blobs:
                    path = blob.get("path")
                    blob_url = blob.get("url")
                    if not blob_url:
                        continue
                    b_resp = await client.get(blob_url, headers=self._get_headers())
                    if b_resp.status_code == 200:
                        b_data = b_resp.json()
                        encoding = b_data.get("encoding", "")
                        content_raw = b_data.get("content", "")
                        if encoding == "base64":
                            decoded = base64.b64decode(content_raw).decode("utf-8", errors="ignore")
                            sources[path] = decoded
                        else:
                            sources[path] = content_raw

        except Exception as e:
            logger.error(f"Error fetching repo sources from GitHub for {owner}/{repo}: {e}")

        return sources

    @staticmethod
    def load_sources_from_local_dir(
        root_dir: Path,
        max_files: int = DEFAULT_CONFIG.scanner_max_file_count,
        max_file_bytes: int = DEFAULT_CONFIG.scanner_max_file_bytes,
    ) -> Dict[str, str]:
        """Loads Python files from local directory snapshot (for fixtures and offline testing)."""
        sources: Dict[str, str] = {}
        import os

        files_loaded = 0
        for dirpath, dirnames, filenames in os.walk(root_dir):
            dirnames[:] = [d for d in dirnames if d not in EXCLUDED_DIRS]
            for filename in filenames:
                if not filename.endswith(".py"):
                    continue
                if files_loaded >= max_files:
                    break
                fp = Path(dirpath) / filename
                rel_path = str(fp.relative_to(root_dir)).replace("\\", "/")
                try:
                    if fp.stat().st_size > max_file_bytes:
                        continue
                    with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                        sources[rel_path] = f.read()
                    files_loaded += 1
                except Exception:
                    continue

        return sources
