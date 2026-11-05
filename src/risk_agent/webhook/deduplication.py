"""Webhook delivery deduplication interfaces and implementations."""

import time
from abc import ABC, abstractmethod
from typing import Dict, Tuple


class DeliveryStore(ABC):
    """Abstract store for webhook delivery IDs to prevent duplicate processing."""

    @abstractmethod
    def is_duplicate(self, delivery_id: str) -> bool:
        """Checks if a delivery ID has already been recorded and is not expired."""
        pass

    @abstractmethod
    def record_delivery(self, delivery_id: str, ttl_seconds: int = 86400) -> bool:
        """Records a delivery ID. Returns True if recorded, False if already present."""
        pass


class InMemoryDeliveryStore(DeliveryStore):
    """In-memory delivery store with TTL expiration for local development and unit tests."""

    def __init__(self, default_ttl_seconds: int = 86400):
        # Maps delivery_id -> expiry_timestamp
        self._deliveries: Dict[str, float] = {}
        self.default_ttl = default_ttl_seconds

    def _cleanup_expired(self, now: float) -> None:
        """Removes expired delivery IDs."""
        expired = [d for d, exp in self._deliveries.items() if exp < now]
        for d in expired:
            del self._deliveries[d]

    def is_duplicate(self, delivery_id: str) -> bool:
        now = time.time()
        self._cleanup_expired(now)
        expiry = self._deliveries.get(delivery_id)
        if expiry is None:
            return False
        return expiry >= now

    def record_delivery(self, delivery_id: str, ttl_seconds: int = None) -> bool:
        now = time.time()
        self._cleanup_expired(now)
        if self.is_duplicate(delivery_id):
            return False
        ttl = ttl_seconds if ttl_seconds is not None else self.default_ttl
        self._deliveries[delivery_id] = now + ttl
        return True

    def clear(self) -> None:
        """Clears all stored deliveries."""
        self._deliveries.clear()

