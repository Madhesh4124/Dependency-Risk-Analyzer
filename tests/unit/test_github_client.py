"""Unit tests for Phase 6 GitHubCommentClient with idempotent upsert."""

import httpx
import pytest

from risk_agent.webhook.github_client import GitHubCommentClient
from risk_agent.webhook.pr_commenter import REPORT_SIGNATURE


@pytest.fixture
def comment_client():
    return GitHubCommentClient(api_base_url="https://api.github.com")


@pytest.mark.anyio
async def test_skip_when_no_token(comment_client):
    """Verifies that commenting gracefully skips when token is empty or None."""
    cid, action = await comment_client.post_or_update_comment(
        repo_full_name="owner/repo",
        pr_number=1,
        comment_body="test body",
        token="",
    )
    assert cid is None
    assert action == "skipped"


@pytest.mark.anyio
async def test_create_new_comment_when_none_exists(comment_client):
    """Verifies POST is executed when no existing report comment is found."""
    posted_payload = None

    def mock_handler(request: httpx.Request) -> httpx.Response:
        nonlocal posted_payload
        # 1. GET existing comments
        if request.method == "GET" and "/issues/1/comments" in str(request.url):
            return httpx.Response(200, json=[{"id": 101, "body": "regular comment"}])
        # 2. POST new comment
        if request.method == "POST" and "/issues/1/comments" in str(request.url):
            posted_payload = request.read().decode("utf-8")
            return httpx.Response(201, json={"id": 202, "body": "new report"})
        return httpx.Response(404)

    async with httpx.AsyncClient(transport=httpx.MockTransport(mock_handler)) as client:
        cid, action = await comment_client.post_or_update_comment(
            repo_full_name="owner/repo",
            pr_number=1,
            comment_body=f"{REPORT_SIGNATURE}\n## Report Content",
            token="ghs_test_token",
            client=client,
        )
        assert cid == 202
        assert action == "created"
        assert posted_payload is not None
        assert REPORT_SIGNATURE in posted_payload


@pytest.mark.anyio
async def test_update_existing_comment_idempotent(comment_client):
    """Verifies PATCH is executed when an existing report comment is found."""
    patched_payload = None

    def mock_handler(request: httpx.Request) -> httpx.Response:
        nonlocal patched_payload
        # 1. GET existing comments
        if request.method == "GET" and "/issues/1/comments" in str(request.url):
            return httpx.Response(
                200,
                json=[
                    {"id": 101, "body": "unrelated user comment"},
                    {"id": 999, "body": f"{REPORT_SIGNATURE}\n## Old Report Content"},
                ],
            )
        # 2. PATCH existing comment
        if request.method == "PATCH" and "/issues/comments/999" in str(request.url):
            patched_payload = request.read().decode("utf-8")
            return httpx.Response(200, json={"id": 999, "body": "updated"})
        return httpx.Response(404)

    async with httpx.AsyncClient(transport=httpx.MockTransport(mock_handler)) as client:
        cid, action = await comment_client.post_or_update_comment(
            repo_full_name="owner/repo",
            pr_number=1,
            comment_body=f"{REPORT_SIGNATURE}\n## Fresh Report Content",
            token="ghs_test_token",
            client=client,
        )
        assert cid == 999
        assert action == "updated"
        assert patched_payload is not None
        assert "Fresh Report Content" in patched_payload


@pytest.mark.anyio
async def test_graceful_degradation_on_api_error(comment_client):
    """Verifies that HTTP errors do not raise exceptions and return failed status."""
    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"message": "Internal GitHub Error"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(mock_handler)) as client:
        cid, action = await comment_client.post_or_update_comment(
            repo_full_name="owner/repo",
            pr_number=1,
            comment_body="body",
            token="ghs_test_token",
            client=client,
        )
        assert cid is None
        assert action == "failed"
