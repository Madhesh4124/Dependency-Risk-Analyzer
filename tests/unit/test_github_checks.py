"""Unit tests for GitHubCheckClient."""

import httpx
import pytest

from risk_agent.models.schemas import RiskReport, SeverityVerdict, VersionBumpType
from risk_agent.security.injection_detector import InjectionPatternType, InjectionResult
from risk_agent.webhook.github_checks import CHECK_NAME, GitHubCheckClient


@pytest.fixture
def check_client():
    return GitHubCheckClient(api_base_url="https://api.github.com")


@pytest.fixture
def risky_report():
    return RiskReport(
        package_name="pydantic",
        old_version="1.10.12",
        new_version="2.6.0",
        bump_type=VersionBumpType.MAJOR,
        verdict=SeverityVerdict.RISKY,
        risk_floor=SeverityVerdict.REVIEW,
        reasons=["Breaking changes detected"],
        verified_claims=[],
        potential_usages=[],
    )


@pytest.fixture
def safe_report():
    return RiskReport(
        package_name="requests",
        old_version="2.28.0",
        new_version="2.28.2",
        bump_type=VersionBumpType.PATCH,
        verdict=SeverityVerdict.NO_RISK_FOUND,
        risk_floor=SeverityVerdict.NO_RISK_FOUND,
        reasons=["Patch update"],
        verified_claims=[],
        potential_usages=[],
    )


@pytest.mark.anyio
async def test_skip_when_missing_token_or_head_sha(check_client, safe_report):
    # No token
    cid, status = await check_client.create_check_run(
        repo_full_name="owner/repo",
        head_sha="abcdef123456",
        report=safe_report,
        token="",
    )
    assert cid is None
    assert status == "skipped"

    # Invalid head_sha
    cid, status = await check_client.create_check_run(
        repo_full_name="owner/repo",
        head_sha="HEAD",
        report=safe_report,
        token="token",
    )
    assert cid is None
    assert status == "skipped"


@pytest.mark.anyio
async def test_risky_verdict_creates_failure_check(check_client, risky_report):
    """Verifies that a RISKY report maps to conclusion: 'failure'."""
    captured_payload = None

    def mock_handler(request: httpx.Request) -> httpx.Response:
        nonlocal captured_payload
        assert request.method == "POST"
        assert "/check-runs" in str(request.url)
        captured_payload = request.read().decode("utf-8")
        return httpx.Response(201, json={"id": 888123})

    async with httpx.AsyncClient(transport=httpx.MockTransport(mock_handler)) as client:
        cid, conclusion = await check_client.create_check_run(
            repo_full_name="owner/repo",
            head_sha="c0ffee123456",
            report=risky_report,
            token="ghs_test_token",
            client=client,
        )
        assert cid == 888123
        assert conclusion == "failure"
        assert '"conclusion":"failure"' in captured_payload
        assert CHECK_NAME in captured_payload


@pytest.mark.anyio
async def test_safe_verdict_creates_success_check(check_client, safe_report):
    """Verifies that a NO_RISK_FOUND report maps to conclusion: 'success'."""
    captured_payload = None

    def mock_handler(request: httpx.Request) -> httpx.Response:
        nonlocal captured_payload
        captured_payload = request.read().decode("utf-8")
        return httpx.Response(201, json={"id": 888124})

    async with httpx.AsyncClient(transport=httpx.MockTransport(mock_handler)) as client:
        cid, conclusion = await check_client.create_check_run(
            repo_full_name="owner/repo",
            head_sha="c0ffee123456",
            report=safe_report,
            token="ghs_test_token",
            client=client,
        )
        assert cid == 888124
        assert conclusion == "success"
        assert '"conclusion":"success"' in captured_payload


@pytest.mark.anyio
async def test_check_run_with_injection_warning(check_client, safe_report):
    """Verifies that an injection result adds security alert into check run title."""
    captured_payload = None

    def mock_handler(request: httpx.Request) -> httpx.Response:
        nonlocal captured_payload
        captured_payload = request.read().decode("utf-8")
        return httpx.Response(201, json={"id": 888125})

    injection = InjectionResult(
        detected=True,
        pattern_type=InjectionPatternType.INSTRUCTION_RESET,
        sanitized_snippet="ignore instructions",
    )

    async with httpx.AsyncClient(transport=httpx.MockTransport(mock_handler)) as client:
        cid, conclusion = await check_client.create_check_run(
            repo_full_name="owner/repo",
            head_sha="c0ffee123456",
            report=safe_report,
            injection_result=injection,
            token="ghs_test_token",
            client=client,
        )
        assert cid == 888125
        assert "SECURITY ALERT" in captured_payload
