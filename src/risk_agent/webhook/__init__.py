"""Webhook handling, deduplication, and FastAPI server."""

from risk_agent.webhook.app import app

__all__ = ["app"]
