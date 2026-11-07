"""Firestore persistence for delivery deduplication and report archives."""

import logging
import time
from typing import Any, Dict, Optional
from risk_agent.models.schemas import RiskReport
from risk_agent.webhook.deduplication import DeliveryStore, InMemoryDeliveryStore

logger = logging.getLogger(__name__)

try:
    from google.cloud import firestore
    HAS_FIRESTORE = True
except ImportError:
    HAS_FIRESTORE = False


class FirestoreDeliveryStore(DeliveryStore):
    """Production DeliveryStore backed by Google Cloud Firestore with in-memory fallback."""

    def __init__(
        self,
        project_id: Optional[str] = None,
        collection_name: str = "deliveries",
        default_ttl_seconds: int = 86400,
    ):
        self.collection_name = collection_name
        self.default_ttl = default_ttl_seconds
        self.project_id = project_id
        self._fallback = InMemoryDeliveryStore(default_ttl_seconds=default_ttl_seconds)
        self._db: Optional[Any] = None
        self._firestore_available = False

        if HAS_FIRESTORE:
            try:
                self._db = firestore.Client(project=project_id)
                self._firestore_available = True
                logger.info(f"Initialized FirestoreDeliveryStore (collection={collection_name})")
            except Exception as e:
                logger.warning(
                    f"Firestore initialization failed ({e}); falling back to InMemoryDeliveryStore."
                )
                self._firestore_available = False
        else:
            logger.warning(
                "google-cloud-firestore not installed; falling back to InMemoryDeliveryStore."
            )

    @property
    def is_using_firestore(self) -> bool:
        return self._firestore_available and self._db is not None

    def is_duplicate(self, delivery_id: str) -> bool:
        if not self.is_using_firestore:
            return self._fallback.is_duplicate(delivery_id)

        try:
            doc_ref = self._db.collection(self.collection_name).document(delivery_id)
            doc = doc_ref.get()
            if not doc.exists:
                return False

            data = doc.to_dict() or {}
            expires_at = data.get("expires_at", 0)
            if time.time() > expires_at:
                return False
            return True
        except Exception as e:
            logger.error(f"Error querying Firestore delivery {delivery_id}: {e}")
            return self._fallback.is_duplicate(delivery_id)

    def record_delivery(self, delivery_id: str, ttl_seconds: Optional[int] = None) -> bool:
        ttl = ttl_seconds if ttl_seconds is not None else self.default_ttl
        now = time.time()
        expires_at = now + ttl

        if not self.is_using_firestore:
            return self._fallback.record_delivery(delivery_id, ttl_seconds=ttl)

        try:
            doc_ref = self._db.collection(self.collection_name).document(delivery_id)
            doc = doc_ref.get()
            if doc.exists:
                data = doc.to_dict() or {}
                if now < data.get("expires_at", 0):
                    return False  # Already exists and not expired

            doc_ref.set(
                {
                    "delivery_id": delivery_id,
                    "recorded_at": now,
                    "ttl_seconds": ttl,
                    "expires_at": expires_at,
                }
            )
            return True
        except Exception as e:
            logger.error(f"Error recording Firestore delivery {delivery_id}: {e}")
            return self._fallback.record_delivery(delivery_id, ttl_seconds=ttl)


class FirestoreReportStore:
    """Stores and retrieves evaluation RiskReport documents in Firestore with in-memory fallback."""

    def __init__(
        self,
        project_id: Optional[str] = None,
        collection_name: str = "evaluation_reports",
    ):
        self.collection_name = collection_name
        self.project_id = project_id
        self._in_memory_reports: Dict[str, Dict[str, Any]] = {}
        self._db: Optional[Any] = None
        self._firestore_available = False

        if HAS_FIRESTORE:
            try:
                self._db = firestore.Client(project=project_id)
                self._firestore_available = True
                logger.info(f"Initialized FirestoreReportStore (collection={collection_name})")
            except Exception as e:
                logger.warning(
                    f"Firestore initialization failed for reports ({e}); falling back to in-memory."
                )
                self._firestore_available = False
        else:
            logger.warning("google-cloud-firestore not installed; falling back to in-memory.")

    @property
    def is_using_firestore(self) -> bool:
        return self._firestore_available and self._db is not None

    def save_report(self, report_id: str, report: RiskReport) -> bool:
        """Persists a RiskReport."""
        report_data = {
            "report_id": report_id,
            "saved_at": time.time(),
            "package_name": report.package_name,
            "old_version": report.old_version,
            "new_version": report.new_version,
            "verdict": report.verdict.value,
            "risk_floor": report.risk_floor.value,
            "report_json": report.model_dump_json(),
        }

        self._in_memory_reports[report_id] = report_data

        if not self.is_using_firestore:
            return True

        try:
            self._db.collection(self.collection_name).document(report_id).set(report_data)
            return True
        except Exception as e:
            logger.error(f"Error persisting report {report_id} to Firestore: {e}")
            return False

    def get_report(self, report_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves a saved report by ID."""
        if self.is_using_firestore:
            try:
                doc = self._db.collection(self.collection_name).document(report_id).get()
                if doc.exists:
                    return doc.to_dict()
            except Exception as e:
                logger.error(f"Error reading report {report_id} from Firestore: {e}")

        return self._in_memory_reports.get(report_id)
