"""Tests for plan_runner: tier execution and context enrichment."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch


class TestExecuteTier:
    """Test parallel tier execution with mocked dispatch."""

    def test_parallel_execution_collects_results(
        self,
        project_dir: Path,
        mock_env_vars: None,
        initialized_db: Path,
        session_manager,
    ) -> None:
        from clawpwn.ai.nli.agent.plan_runner import execute_tier_parallel

        session_manager.create_project(str(project_dir))
        session_manager.save_plan(
            [
                {"description": "Fingerprint", "tool": "fingerprint_target"},
                {"description": "Web search", "tool": "web_search"},
            ]
        )

        steps = [
            {"step_number": 1, "description": "Fingerprint", "tool": "fingerprint_target"},
            {"step_number": 2, "description": "Web search", "tool": "web_search"},
        ]

        with patch(
            "clawpwn.ai.nli.agent.plan_runner.dispatch_tool",
            return_value="Result: all good",
        ):
            results = execute_tier_parallel(
                steps,
                "http://target/",
                {},
                project_dir,
                session_manager,
                emit=lambda msg: None,
                progress=[],
            )

        assert len(results) == 2
        assert all(not r["failed"] for r in results)

    def test_failed_dispatch_marked_as_failed(
        self,
        project_dir: Path,
        mock_env_vars: None,
        initialized_db: Path,
        session_manager,
    ) -> None:
        from clawpwn.ai.nli.agent.plan_runner import execute_tier_parallel

        session_manager.create_project(str(project_dir))
        session_manager.save_plan(
            [
                {"description": "Bad scan", "tool": "web_scan:sqlmap"},
            ]
        )

        steps = [
            {"step_number": 1, "description": "Bad scan", "tool": "web_scan:sqlmap"},
        ]

        with patch(
            "clawpwn.ai.nli.agent.plan_runner.dispatch_tool",
            return_value="Tool 'web_scan' failed: connection refused",
        ):
            results = execute_tier_parallel(
                steps,
                "http://target/",
                {},
                project_dir,
                session_manager,
                emit=lambda msg: None,
                progress=[],
            )

        assert len(results) == 1
        assert results[0]["failed"] is True


class TestContextEnrichment:
    """Test context extraction from tier results."""

    def test_enrich_detects_phpmyadmin(self) -> None:
        from clawpwn.ai.nli.agent.plan_runner import enrich_context

        context: dict = {"app_hint": "", "techs": []}
        results = [
            {
                "tool": "fingerprint_target",
                "result_text": "Server: Apache, Technology: phpMyAdmin 5.2, PHP 8.1",
            }
        ]
        enrich_context(context, results)
        assert context["app_hint"] == "phpmyadmin"
        assert "php" in context["techs"]
        assert "apache" in context["techs"]

    def test_enrich_detects_wordpress(self) -> None:
        from clawpwn.ai.nli.agent.plan_runner import enrich_context

        context: dict = {"app_hint": "", "techs": []}
        results = [
            {
                "tool": "fingerprint_target",
                "result_text": "WordPress 6.4 on nginx with MySQL",
            }
        ]
        enrich_context(context, results)
        assert context["app_hint"] == "wordpress"
        assert "nginx" in context["techs"]
        assert "mysql" in context["techs"]

    def test_enrich_no_fingerprint_no_change(self) -> None:
        from clawpwn.ai.nli.agent.plan_runner import enrich_context

        context: dict = {"app_hint": "", "techs": []}
        results = [
            {
                "tool": "web_scan:builtin",
                "result_text": "Found phpMyAdmin vulnerability",
            }
        ]
        enrich_context(context, results)
        # Only fingerprint_target results trigger enrichment
        assert context["app_hint"] == ""

    def test_enrich_extracts_services_from_network_scan(self) -> None:
        from clawpwn.ai.nli.agent.plan_runner import enrich_context

        context: dict = {"app_hint": "", "techs": []}
        results = [
            {
                "tool": "network_scan",
                "tool_name": "network_scan",
                "result_text": (
                    "Host scan of 172.17.0.2 complete.\nServices:\n"
                    "  21/tcp: vsftpd 2.3.4\n"
                    "  22/tcp: OpenSSH 4.7p1\n"
                    "  80/tcp: Apache httpd 2.2.8"
                ),
            }
        ]
        enrich_context(context, results)
        services = context["services"]
        assert len(services) == 3
        assert services[0] == {"port": 21, "product": "vsftpd 2.3.4"}
        assert services[1] == {"port": 22, "product": "openssh 4.7p1"}
        assert services[2] == {"port": 80, "product": "apache httpd 2.2.8"}

    def test_enrich_no_duplicate_services(self) -> None:
        from clawpwn.ai.nli.agent.plan_runner import enrich_context

        context: dict = {"services": [{"port": 21, "product": "vsftpd 2.3.4"}]}
        results = [
            {
                "tool": "network_scan",
                "tool_name": "network_scan",
                "result_text": "  21/tcp: vsftpd 2.3.4\n  22/tcp: OpenSSH 4.7p1",
            }
        ]
        enrich_context(context, results)
        assert len(context["services"]) == 2


class TestWebScanServiceKeywords:
    """Test that service keywords flow from context to web_scan params."""

    def test_web_scan_gets_service_keywords(self) -> None:
        from clawpwn.ai.nli.agent.plan_helpers import step_to_dispatch_params

        ctx = {
            "services": [
                {"port": 21, "product": "vsftpd 2.3.4"},
                {"port": 22, "product": "OpenSSH 4.7p1"},
            ]
        }
        name, params = step_to_dispatch_params("web_scan:searchsploit", "192.168.1.10", ctx)
        assert name == "web_scan"
        assert params["service_keywords"] == ["vsftpd 2.3.4", "OpenSSH 4.7p1"]

    def test_web_scan_no_keywords_without_services(self) -> None:
        from clawpwn.ai.nli.agent.plan_helpers import step_to_dispatch_params

        name, params = step_to_dispatch_params("web_scan:searchsploit", "192.168.1.10", {})
        assert name == "web_scan"
        assert "service_keywords" not in params


class TestNetworkScanOutput:
    """Test that network scan executor includes service versions."""

    def test_format_services(self) -> None:
        from types import SimpleNamespace

        from clawpwn.ai.nli.tool_executors.scan_executors.network import _format_services

        host = SimpleNamespace(
            services=[
                SimpleNamespace(
                    port=21, protocol="tcp", product="vsftpd", version="2.3.4", name="ftp"
                ),
                SimpleNamespace(
                    port=22, protocol="tcp", product="OpenSSH", version="4.7p1", name="ssh"
                ),
                SimpleNamespace(port=80, protocol="tcp", product="", version="", name="http"),
            ]
        )
        result = _format_services(host)
        assert "21/tcp: vsftpd 2.3.4" in result
        assert "22/tcp: OpenSSH 4.7p1" in result
        assert "80/tcp: http" in result
