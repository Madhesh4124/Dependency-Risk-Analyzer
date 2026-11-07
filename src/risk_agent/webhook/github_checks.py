"""GitHub Checks API Client for Phase 6.

Creates and updates GitHub Check Runs to physically pass or block PR merges based on evaluation verdicts:
- RISKY -> conclusion: "failure" (blocks merge)
- REVIEW -> conclusion: "action_required" / "neutral"
- NO_RISK_FOUND -> conclusion: "success" (green check)
"""

from datetime import datetime, timezone
import logging
from typing import Any, Dict, Optional, Tuple
import httpx

from risk_agent.models.schemas import RiskReport, SeverityVerdict
from risk_agent.security.injection_detector import InjectionResult

logger = logging.getLogger(__name__)

CHECK_NAME = "Dependency Upgrade Risk Analysis"


class GitHubCheckClient:
    """Handles creating and updating GitHub Check Runs on PR head commits."""

    def __init__(self, api_base_url: str = "https://api.github.com"):
        self.api_base_url = api_base_url.rstrip("/")

    async def create_check_run(
        self,
        repo_full_name: str,
        head_sha: str,
        report: RiskReport,
        injection_result: Optional[InjectionResult] = None,
        token: str = "",
        client: Optional[httpx.AsyncClient] = None,
    ) -> Tuple[Optional[int], str]:
        """Creates a completed Check Run for the head commit of a PR.

        Maps RiskReport verdict to GitHub Check Run conclusion:
        - NO_RISK_FOUND -> "success"
        - REVIEW -> "neutral"
        - RISKY -> "failure"

        Returns:
            Tuple[Optional[int], str]: (check_run_id, status_string)
        """
        if not token:
            logger.warning("No GitHub token available; skipping check run for %s @ %s", repo_full_name, head_sha)
            return None, "skipped"

        if not head_sha or head_sha == "HEAD":
            logger.warning("Invalid head SHA '%s'; skipping check run for %s", head_sha, repo_full_name)
            return None, "skipped"

        # Map verdict to GitHub Check conclusion
        verdict = report.verdict
        if verdict == SeverityVerdict.NO_RISK_FOUND:
            conclusion = "success"
            title = "Passed: No dependency upgrade risk detected"
            summary = f"Upgrade for `{report.package_name}` ({report.old_version} ➔ {report.new_version}) passed all compatibility and AST checks."
        elif verdict == SeverityVerdict.REVIEW:
            conclusion = "neutral"
            title = "Warning: Manual dependency review required"
            summary = f"Upgrade for `{report.package_name}` ({report.old_version} ➔ {report.new_version}) requires manual review. Reason: {'; '.join(report.reasons[:2])}"
        else:
            conclusion = "failure"
            title = "Failed: Breaking changes or upgrade risks detected"
            summary = f"Upgrade for `{report.package_name}` ({report.old_version} ➔ {report.new_version}) identified breaking changes or affected codebase usages."

        # If injection was detected, ensure summary highlights security quarantine
        if injection_result and injection_result.detected:
            title = f"{title} [SECURITY ALERT]"
            summary = f"⚠️ Prompt injection attempt detected & defused!\n\n{summary}"

        now_iso = datetime.now(timezone.utc).isoformat()
        payload: Dict[str, Any] = {
            "name": CHECK_NAME,
            "head_sha": head_sha,
            "status": "completed",
            "conclusion": conclusion,
            "completed_at": now_iso,
            "output": {
                "title": title,
                "summary": summary,
                "text": f"**Final Verdict:** `{verdict.value}`\n**Deterministic Risk Floor:** `{report.risk_floor.value}`\n**Verified Claims:** {len(report.verified_claims)}\n**Affected Call Sites:** {len(report.potential_usages)}",
            },
        }

        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

        owns_client = False
        if client is None:
            client = httpx.AsyncClient(timeout=15.0)
            owns_client = True

        url = f"{self.api_base_url}/repos/{repo_full_name}/check-runs"
        try:
            resp = await client.post(url, headers=headers, json=payload)
            if resp.status_code in (200, 201):
                check_id = resp.json().get("id")
                logger.info(
                    "Successfully created Check Run %s for %s @ %s (conclusion=%s)",
                    check_id,
                    repo_full_name,
                    head_sha[:7],
                    conclusion,
                )
                return check_id, conclusion
            else:
                logger.warning(
                    "Failed to create Check Run on %s @ %s (HTTP %d): %s",
                    repo_full_name,
                    head_sha[:7],
                    resp.status_code,
                    resp.text,
                )
                return None, "failed"
        except Exception as e:
            logger.error("Error creating Check Run for %s @ %s: %s", repo_full_name, head_sha, e)
            return None, "failed"
        finally:
            if owns_client:
                await client.aclose()
