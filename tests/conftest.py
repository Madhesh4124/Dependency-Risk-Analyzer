"""Shared pytest fixtures for hermetic Google Cloud Model Armor & Webhook testing."""

import sys
from types import SimpleNamespace
import pytest


class _StubModelArmorClient:
    """Schema-faithful clean stub for ModelArmorClient during local unit/integration tests."""

    def __init__(self, *args, **kwargs):
        pass

    def sanitize_user_prompt(self, request=None, **kwargs):
        from google.cloud import modelarmor_v1

        return SimpleNamespace(
            sanitization_result=SimpleNamespace(
                invocation_result=modelarmor_v1.InvocationResult.SUCCESS,
                filter_match_state=modelarmor_v1.FilterMatchState.NO_MATCH_FOUND,
                filter_results={},
            )
        )

    def sanitize_model_response(self, request=None, **kwargs):
        from google.cloud import modelarmor_v1

        return SimpleNamespace(
            sanitization_result=SimpleNamespace(
                invocation_result=modelarmor_v1.InvocationResult.SUCCESS,
                filter_match_state=modelarmor_v1.FilterMatchState.NO_MATCH_FOUND,
                filter_results={},
            )
        )


@pytest.fixture(autouse=True)
def _stub_model_armor_client(monkeypatch):
    """Prevents accidental live GCP Model Armor network calls in hermetic tests."""
    from google.cloud import modelarmor_v1

    monkeypatch.setattr(modelarmor_v1, "ModelArmorClient", _StubModelArmorClient)

    app_mod = sys.modules.get("risk_agent.webhook.app")
    if app_mod is not None and hasattr(app_mod, "injection_detector"):
        app_mod.injection_detector._client = None

    yield

    app_mod = sys.modules.get("risk_agent.webhook.app")
    if app_mod is not None and hasattr(app_mod, "injection_detector"):
        app_mod.injection_detector._client = None
