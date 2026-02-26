"""ExperienceManager — cross-project learning from scan results."""

import logging
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse

from clawpwn.db.experience_init import (
    EXPERIENCE_DB_PATH,
    get_experience_session,
    init_experience_db,
)
from clawpwn.db.experience_models import Experience

logger = logging.getLogger(__name__)


class ExperienceManager:
    """Records and queries scan experience across projects."""

    def __init__(self, db_path: Path = EXPERIENCE_DB_PATH):
        self.db_path = db_path
        self._session = None

    def _get_session(self):
        if self._session is None:
            try:
                init_experience_db(self.db_path)
                self._session = get_experience_session(self.db_path)
            except Exception:
                logger.warning("Failed to open experience DB", exc_info=True)
        return self._session

    def record(
        self,
        check_type: str,
        domain: str,
        result: str,
        confidence: str = "medium",
        payload: str | None = None,
        tech: str | None = None,
        evidence: str | None = None,
    ) -> None:
        """Record a scan experience, upserting on (check_type, domain, payload)."""
        session = self._get_session()
        if session is None:
            return
        try:
            self._upsert(session, check_type, domain, result, confidence, payload, tech, evidence)
            session.commit()
        except Exception:
            logger.warning("Failed to record experience", exc_info=True)
            session.rollback()

    def get_effective_payloads(
        self,
        check_type: str,
        domain: str | None = None,
    ) -> list[str]:
        """Return payloads that worked, sorted by hit_count desc."""
        session = self._get_session()
        if session is None:
            return []
        try:
            query = (
                session.query(Experience)
                .filter_by(check_type=check_type, result="vulnerable")
                .filter(Experience.effective_payload.isnot(None))
            )
            if domain:
                query = query.filter_by(target_domain=domain)
            rows = query.order_by(Experience.hit_count.desc()).all()
            return [r.effective_payload for r in rows]
        except Exception:
            logger.warning("Failed to query payloads", exc_info=True)
            return []

    def get_target_history(self, domain: str) -> list[Experience]:
        """Return all experience records for a domain."""
        session = self._get_session()
        if session is None:
            return []
        try:
            return (
                session.query(Experience)
                .filter_by(target_domain=domain)
                .order_by(Experience.updated_at.desc())
                .all()
            )
        except Exception:
            logger.warning("Failed to query history", exc_info=True)
            return []

    def was_previously_clean(self, check_type: str, domain: str, min_hits: int = 3) -> bool:
        """True if we've checked this N+ times and never found anything."""
        session = self._get_session()
        if session is None:
            return False
        try:
            row = (
                session.query(Experience)
                .filter_by(
                    check_type=check_type,
                    target_domain=domain,
                    result="not_vulnerable",
                    effective_payload=None,
                )
                .first()
            )
            return row is not None and row.hit_count >= min_hits
        except Exception:
            logger.warning("Failed to check clean status", exc_info=True)
            return False

    def get_stats(self) -> dict:
        """Return summary stats for the experience DB."""
        session = self._get_session()
        if session is None:
            return {}
        try:
            total = session.query(Experience).count()
            vuln = session.query(Experience).filter_by(result="vulnerable").count()
            domains = session.query(Experience.target_domain).distinct().count()
            return {
                "total_records": total,
                "vulnerable": vuln,
                "not_vulnerable": total - vuln,
                "unique_domains": domains,
            }
        except Exception:
            logger.warning("Failed to get stats", exc_info=True)
            return {}

    def clear(self) -> None:
        """Delete all experience records."""
        session = self._get_session()
        if session is None:
            return
        try:
            session.query(Experience).delete()
            session.commit()
        except Exception:
            logger.warning("Failed to clear experience DB", exc_info=True)
            session.rollback()

    @staticmethod
    def domain_from_url(url: str) -> str:
        """Extract the netloc (domain) from a URL."""
        if url and "://" not in url:
            url = f"http://{url}"
        return urlparse(url).netloc or url

    @staticmethod
    def _upsert(
        session,
        check_type,
        domain,
        result,
        confidence,
        payload,
        tech,
        evidence,
    ):
        existing = (
            session.query(Experience)
            .filter_by(
                check_type=check_type,
                target_domain=domain,
                effective_payload=payload,
            )
            .first()
        )
        if existing:
            existing.hit_count += 1
            existing.updated_at = datetime.now(UTC)
            existing.result = result
            existing.confidence = confidence
            if tech:
                existing.target_tech = tech
            if evidence:
                existing.evidence_summary = evidence
        else:
            session.add(
                Experience(
                    check_type=check_type,
                    target_domain=domain,
                    target_tech=tech,
                    result=result,
                    confidence=confidence,
                    effective_payload=payload,
                    evidence_summary=evidence,
                )
            )
