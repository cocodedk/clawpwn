"""Tests for the experience database and ExperienceManager."""

from pathlib import Path

import pytest

from clawpwn.db.experience_init import get_experience_session, init_experience_db
from clawpwn.db.experience_models import Experience
from clawpwn.modules.experience import ExperienceManager


@pytest.fixture
def exp_db_path(tmp_path):
    """Create a temporary experience database."""
    db_path = tmp_path / "experience.db"
    init_experience_db(db_path)
    return db_path


@pytest.fixture
def exp_manager(exp_db_path):
    """Return an ExperienceManager backed by a temp database."""
    return ExperienceManager(db_path=exp_db_path)


class TestExperienceInit:
    def test_init_creates_db(self, tmp_path):
        db_path = tmp_path / "test.db"
        init_experience_db(db_path)
        assert db_path.exists()

    def test_get_session(self, exp_db_path):
        session = get_experience_session(exp_db_path)
        assert session is not None
        assert session.query(Experience).count() == 0


class TestExperienceRecord:
    def test_record_creates_entry(self, exp_manager):
        exp_manager.record(
            "sql_injection",
            "example.com",
            "vulnerable",
            confidence="high",
            payload="' OR 1=1--",
            evidence="SQL error found",
        )
        history = exp_manager.get_target_history("example.com")
        assert len(history) == 1
        assert history[0].check_type == "sql_injection"
        assert history[0].result == "vulnerable"
        assert history[0].effective_payload == "' OR 1=1--"
        assert history[0].hit_count == 1

    def test_record_upserts_on_same_key(self, exp_manager):
        for _ in range(3):
            exp_manager.record("sql_injection", "example.com", "vulnerable", payload="' OR 1=1--")
        history = exp_manager.get_target_history("example.com")
        assert len(history) == 1
        assert history[0].hit_count == 3

    def test_record_different_payloads_are_separate(self, exp_manager):
        exp_manager.record("xss", "example.com", "vulnerable", payload="<script>")
        exp_manager.record("xss", "example.com", "vulnerable", payload="<img src=x>")
        history = exp_manager.get_target_history("example.com")
        assert len(history) == 2

    def test_record_not_vulnerable(self, exp_manager):
        exp_manager.record("sql_injection", "safe.com", "not_vulnerable")
        history = exp_manager.get_target_history("safe.com")
        assert len(history) == 1
        assert history[0].result == "not_vulnerable"

    def test_record_with_tech(self, exp_manager):
        exp_manager.record("sql_injection", "example.com", "vulnerable", tech="nginx/1.18, PHP/7.4")
        history = exp_manager.get_target_history("example.com")
        assert history[0].target_tech == "nginx/1.18, PHP/7.4"


class TestGetEffectivePayloads:
    def test_returns_payloads_sorted_by_hit_count(self, exp_manager):
        for _ in range(3):
            exp_manager.record("sql_injection", "example.com", "vulnerable", payload="A")
        exp_manager.record("sql_injection", "example.com", "vulnerable", payload="B")
        payloads = exp_manager.get_effective_payloads("sql_injection")
        assert payloads == ["A", "B"]

    def test_returns_empty_when_no_vulnerables(self, exp_manager):
        exp_manager.record("xss", "safe.com", "not_vulnerable")
        assert exp_manager.get_effective_payloads("xss") == []

    def test_filters_by_domain(self, exp_manager):
        exp_manager.record("xss", "a.com", "vulnerable", payload="<script>")
        exp_manager.record("xss", "b.com", "vulnerable", payload="<img>")
        assert exp_manager.get_effective_payloads("xss", domain="a.com") == ["<script>"]

    def test_returns_all_domains_when_no_filter(self, exp_manager):
        exp_manager.record("xss", "a.com", "vulnerable", payload="<script>")
        exp_manager.record("xss", "b.com", "vulnerable", payload="<img>")
        assert len(exp_manager.get_effective_payloads("xss")) == 2


class TestWasPreviouslyClean:
    def test_returns_false_when_no_data(self, exp_manager):
        assert exp_manager.was_previously_clean("xss", "new.com") is False

    def test_returns_false_below_min_hits(self, exp_manager):
        exp_manager.record("xss", "safe.com", "not_vulnerable")
        assert exp_manager.was_previously_clean("xss", "safe.com", min_hits=3) is False

    def test_returns_true_at_min_hits(self, exp_manager):
        for _ in range(3):
            exp_manager.record("xss", "safe.com", "not_vulnerable")
        assert exp_manager.was_previously_clean("xss", "safe.com", min_hits=3) is True

    def test_returns_false_when_vulnerable(self, exp_manager):
        for _ in range(5):
            exp_manager.record("xss", "vuln.com", "vulnerable", payload="<script>")
        assert exp_manager.was_previously_clean("xss", "vuln.com") is False


class TestGetStats:
    def test_empty_stats(self, exp_manager):
        stats = exp_manager.get_stats()
        assert stats["total_records"] == 0
        assert stats["unique_domains"] == 0

    def test_stats_after_records(self, exp_manager):
        exp_manager.record("xss", "a.com", "vulnerable", payload="<script>")
        exp_manager.record("sqli", "b.com", "not_vulnerable")
        stats = exp_manager.get_stats()
        assert stats["total_records"] == 2
        assert stats["vulnerable"] == 1
        assert stats["not_vulnerable"] == 1
        assert stats["unique_domains"] == 2


class TestClear:
    def test_clear_removes_all(self, exp_manager):
        exp_manager.record("xss", "a.com", "vulnerable", payload="<script>")
        exp_manager.record("sqli", "b.com", "not_vulnerable")
        exp_manager.clear()
        assert exp_manager.get_stats()["total_records"] == 0


class TestDomainFromUrl:
    def test_extracts_netloc(self):
        assert ExperienceManager.domain_from_url("https://example.com/path") == "example.com"

    def test_with_port(self):
        assert ExperienceManager.domain_from_url("http://localhost:8080/") == "localhost:8080"

    def test_bare_string_fallback(self):
        assert ExperienceManager.domain_from_url("not-a-url") == "not-a-url"


class TestGracefulFailure:
    def test_record_with_bad_path(self):
        mgr = ExperienceManager(db_path=Path("/nonexistent/dir/nope.db"))
        mgr.record("xss", "a.com", "vulnerable")

    def test_get_payloads_with_bad_path(self):
        mgr = ExperienceManager(db_path=Path("/nonexistent/dir/nope.db"))
        assert mgr.get_effective_payloads("xss") == []

    def test_was_clean_with_bad_path(self):
        mgr = ExperienceManager(db_path=Path("/nonexistent/dir/nope.db"))
        assert mgr.was_previously_clean("xss", "a.com") is False

    def test_get_stats_with_bad_path(self):
        mgr = ExperienceManager(db_path=Path("/nonexistent/dir/nope.db"))
        assert mgr.get_stats() == {}


class TestScannerExperienceIntegration:
    def test_scanner_has_experience(self, project_dir):
        from clawpwn.modules.scanner import Scanner

        scanner = Scanner(project_dir)
        assert scanner.experience is not None

    def test_active_scanner_prioritizes_payloads(self, tmp_path, project_dir):
        from clawpwn.modules.scanner.active import ActiveScanner

        exp = ExperienceManager(db_path=tmp_path / "exp.db")
        exp.record("sql_injection", "example.com", "vulnerable", payload="' OR 1=1--")

        scanner = ActiveScanner(project_dir, experience=exp)
        defaults = ["'", "''", "' OR '1'='1"]
        result = scanner._prioritize("sql_injection", "https://example.com", defaults)
        assert result[0] == "' OR 1=1--"
        assert "'" in result
        assert "' OR '1'='1" in result

    def test_active_scanner_no_experience(self, project_dir):
        from clawpwn.modules.scanner.active import ActiveScanner

        scanner = ActiveScanner(project_dir, experience=None)
        assert scanner._prioritize("xss", "https://example.com", ["a", "b"]) == ["a", "b"]

    def test_passive_scanner_extract_tech(self, project_dir):
        from clawpwn.modules.scanner.passive import PassiveScanner
        from clawpwn.tools.http import HTTPResponse

        scanner = PassiveScanner(project_dir)
        response = HTTPResponse(
            url="https://example.com",
            status_code=200,
            headers={"Server": "nginx/1.18", "X-Powered-By": "PHP/7.4"},
            body="",
            cookies={},
            response_time=0.1,
        )
        tech = scanner.extract_tech(response)
        assert "nginx/1.18" in tech
        assert "PHP/7.4" in tech

    def test_passive_scanner_extract_tech_none(self, project_dir):
        from clawpwn.modules.scanner.passive import PassiveScanner
        from clawpwn.tools.http import HTTPResponse

        scanner = PassiveScanner(project_dir)
        response = HTTPResponse(
            url="https://example.com",
            status_code=200,
            headers={},
            body="",
            cookies={},
            response_time=0.1,
        )
        assert scanner.extract_tech(response) is None
