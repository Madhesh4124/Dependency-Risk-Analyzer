"""GitHub REST API client for Phase 6 PR commenting and idempotent updates.

Provides idempotent upsert of impact assessment comments on pull requests.
Uses hidden signature marker to update existing comments in-place instead of spamming.
"""

import logging
from typing import Optional, Tuple
import httpx

from risk_agent.webhook.pr_commenter import REPORT_SIGNATURE

logger = logging.getLogger(__name__)


class GitHubCommentClient:
    """Handles posting and updating comments on GitHub Pull Requests."""

    def __init__(self, api_base_url: str = "https://api.github.com"):
        self.api_base_url = api_base_url.rstrip("/")

    async def post_or_update_comment(
        self,
        repo_full_name: str,
        pr_number: int,
        comment_body: str,
        token: str,
        client: Optional[httpx.AsyncClient] = None,
    ) -> Tuple[Optional[int], str]:
        """Idempotently posts or updates a PR comment with the analyzer report.

        Returns:
            Tuple[Optional[int], str]: (comment_id, action_taken)
            action_taken can be: "created", "updated", "failed", or "skipped"
        """
        if not token:
            logger.warning("No GitHub token available; skipping PR comment for %s#%d", repo_full_name, pr_number)
            return None, "skipped"

        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

        owns_client = False
        if client is None:
            client = httpx.AsyncClient(timeout=15.0)
            owns_client = True

        try:
            # 1. Search for existing comments on this PR
            comments_url = f"{self.api_base_url}/repos/{repo_full_name}/issues/{pr_number}/comments?per_page=100"
            resp = await client.get(comments_url, headers=headers)

            existing_comment_id: Optional[int] = None
            if resp.status_code == 200:
                comments = resp.json()
                for comment in comments:
                    body = comment.get("body", "")
                    if REPORT_SIGNATURE in body:
                        existing_comment_id = comment.get("id")
                        break
            else:
                logger.warning(
                    "Failed to fetch existing comments for %s#%d (HTTP %d): %s",
                    repo_full_name,
                    pr_number,
                    resp.status_code,
                    resp.text,
                )

            # 2. Update existing comment in-place (Idempotent PATCH)
            if existing_comment_id:
                patch_url = f"{self.api_base_url}/repos/{repo_full_name}/issues/comments/{existing_comment_id}"
                patch_resp = await client.patch(patch_url, headers=headers, json={"body": comment_body})
                if patch_resp.status_code in (200, 201):
                    logger.info("Successfully updated PR comment %d on %s#%d", existing_comment_id, repo_full_name, pr_number)
                    return existing_comment_id, "updated"
                else:
                    logger.warning(
                        "Failed to update comment %d on %s#%d (HTTP %d): %s",
                        existing_comment_id,
                        repo_full_name,
                        pr_number,
                        patch_resp.status_code,
                        patch_resp.text,
                    )
                    return existing_comment_id, "failed"

            # 3. Create new comment (POST)
            post_url = f"{self.api_base_url}/repos/{repo_full_name}/issues/{pr_number}/comments"
            post_resp = await client.post(post_url, headers=headers, json={"body": comment_body})
            if post_resp.status_code in (200, 201):
                new_id = post_resp.json().get("id")
                logger.info("Successfully posted new PR comment %s on %s#%d", new_id, repo_full_name, pr_number)
                return new_id, "created"
            else:
                logger.warning(
                    "Failed to post PR comment on %s#%d (HTTP %d): %s",
                    repo_full_name,
                    pr_number,
                    post_resp.status_code,
                    post_resp.text,
                )
                return None, "failed"

        except Exception as e:
            logger.error("Unexpected error in PR commenter for %s#%d: %s", repo_full_name, pr_number, e)
            return None, "failed"
        finally:
            if owns_client:
                await client.aclose()
