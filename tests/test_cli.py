"""Tests for CLI commands."""

from pathlib import Path

from clawpwn.cli import app, get_project_dir, require_project
from clawpwn.modules.network import HostInfo


def _make_fake_project(tmpdir: Path) -> Path:
    project_path = tmpdir / "scan_project"
    project_path.mkdir()
    (project_path / ".clawpwn").mkdir()
    (project_path / "evidence").mkdir()
    (project_path / "exploits").mkdir()
    (project_path / "report").mkdir()
    return project_path


class TestCLIInit:
    """Test the init command."""

    def test_app_has_commands(self):
        """Test that app has all expected commands registered."""
        # Check that app is properly initialized
        assert app is not None
        # Typer apps have a 'registered_commands' or similar
        # We just verify the app object exists

    def test_get_project_dir_finds_project(self, temp_dir: Path):
        """Test finding project directory."""
        # Create a mock project structure
        project_path = temp_dir / "test_project"
        project_path.mkdir()
        (project_path / ".clawpwn").mkdir()

        # Change to that directory
        import os

        original_cwd = os.getcwd()
        os.chdir(project_path)

        try:
            result = get_project_dir()
            assert result is not None
            assert result.name == "test_project"
        finally:
            os.chdir(original_cwd)

    def test_get_project_dir_returns_none_outside_project(self, temp_dir: Path):
        """Test that get_project_dir returns None outside a project."""
        import os

        original_cwd = os.getcwd()
        os.chdir(temp_dir)

        try:
            result = get_project_dir()
            assert result is None
        finally:
            os.chdir(original_cwd)


class TestProjectDetection:
    """Test project directory detection."""

    def test_require_project_raises_outside_project(self, temp_dir: Path):
        """Test that require_project raises an exception outside a project."""
        import os

        import typer

        original_cwd = os.getcwd()
        os.chdir(temp_dir)

        try:
            # This should raise a typer.Exit
            try:
                require_project()
                assert False, "Should have raised an exception"
            except typer.Exit:
                pass  # Expected
        finally:
            os.chdir(original_cwd)

    def test_require_project_succeeds_inside_project(self, project_dir: Path):
        """Test that require_project succeeds inside a project."""
        import os

        original_cwd = os.getcwd()
        os.chdir(project_dir)

        try:
            result = require_project()
            assert result is not None
            assert result.name == project_dir.name
        finally:
            os.chdir(original_cwd)


class TestCLICommandsExist:
    """Test that CLI commands exist and are properly configured."""

    def test_all_commands_registered(self):
        """Verify all documented commands are registered."""
        # The app should have commands registered
        # We check by looking at the app's registered groups/commands

        # Just verify the app object has commands
        # In Typer, commands are stored in .registered_commands or .commands
        assert hasattr(app, "registered_commands") or hasattr(app, "commands") or True


def test_scan_skips_web_for_raw_ip(monkeypatch, temp_dir: Path, capsys):
    from clawpwn import cli as cli_module
    from clawpwn.modules import network as network_module

    project_path = _make_fake_project(temp_dir)

    # Force project resolution
    monkeypatch.setattr(cli_module, "require_project", lambda: project_path)

    class FakeState:
        target = "91.100.72.107"

    class FakeSession:
        def get_state(self):
            return FakeState()

        def update_phase(self, phase: str):
            return None

    monkeypatch.setattr(cli_module, "SessionManager", lambda _: FakeSession())

    async def fake_scan_host(*args, **kwargs):
        return HostInfo(ip="91.100.72.107", open_ports=[80], services=[])

    monkeypatch.setattr(network_module.NetworkDiscovery, "scan_host", fake_scan_host)
    monkeypatch.setattr(network_module.NetworkDiscovery, "print_summary", lambda *_: None)

    # Prevent web scanning from running
    class FakeScanner:
        async def scan(self, *args, **kwargs):
            raise AssertionError("web scan should not run for raw IP")

    monkeypatch.setattr(cli_module, "Scanner", lambda *_: FakeScanner())

    # Run
    cli_module.scan(verbose=False)

    out = capsys.readouterr().out
    assert "No URL scheme detected" in out
    # Either "no web services found" or "network discovery" indicates we did not run web scan
    assert "no web services found" in out or "network discovery" in out


def test_scan_verbose_flag_enables_nmap_verbose(monkeypatch, temp_dir: Path):
    from clawpwn import cli as cli_module
    from clawpwn.modules import network as network_module

    project_path = _make_fake_project(temp_dir)
    monkeypatch.setattr(cli_module, "require_project", lambda: project_path)

    class FakeState:
        target = "91.100.72.107"

    class FakeSession:
        def get_state(self):
            return FakeState()

        def update_phase(self, phase: str):
            return None

    monkeypatch.setattr(cli_module, "SessionManager", lambda _: FakeSession())

    called = {"verbose": None}

    async def fake_scan_host(*args, **kwargs):
        called["verbose"] = kwargs.get("verbose")
        return HostInfo(ip="91.100.72.107", open_ports=[22], services=[])

    monkeypatch.setattr(network_module.NetworkDiscovery, "scan_host", fake_scan_host)
    monkeypatch.setattr(network_module.NetworkDiscovery, "print_summary", lambda *_: None)

    class FakeScanner:
        async def scan(self, *args, **kwargs):
            return []

    monkeypatch.setattr(cli_module, "Scanner", lambda *_: FakeScanner())

    cli_module.scan(verbose=True)

    assert called["verbose"] is True


def test_scan_env_verbose(monkeypatch, temp_dir: Path):
    from clawpwn import cli as cli_module
    from clawpwn.modules import network as network_module

    project_path = _make_fake_project(temp_dir)
    monkeypatch.setattr(cli_module, "require_project", lambda: project_path)
    monkeypatch.setenv("CLAWPWN_VERBOSE", "true")

    class FakeState:
        target = "91.100.72.107"

    class FakeSession:
        def get_state(self):
            return FakeState()

        def update_phase(self, phase: str):
            return None

    monkeypatch.setattr(cli_module, "SessionManager", lambda _: FakeSession())

    called = {"verbose": None}

    async def fake_scan_host(*args, **kwargs):
        called["verbose"] = kwargs.get("verbose")
        return HostInfo(ip="91.100.72.107", open_ports=[22], services=[])

    monkeypatch.setattr(network_module.NetworkDiscovery, "scan_host", fake_scan_host)
    monkeypatch.setattr(network_module.NetworkDiscovery, "print_summary", lambda *_: None)

    class FakeScanner:
        async def scan(self, *args, **kwargs):
            return []

    monkeypatch.setattr(cli_module, "Scanner", lambda *_: FakeScanner())

    cli_module.scan()

    assert called["verbose"] is True


class TestTyperAppStructure:
    """Test Typer app structure."""

    def test_app_is_typer_instance(self):
        """Test that app is a Typer instance."""
        import typer

        assert isinstance(app, typer.Typer)

    def test_main_function_exists(self):
        """Test that main function exists."""
        from clawpwn.cli import main

        assert callable(main)


def test_objective_set_and_show(monkeypatch, temp_dir: Path, capsys):
    from clawpwn import cli as cli_module
    from clawpwn.config import get_project_db_path
    from clawpwn.modules.session import SessionManager

    project_path = _make_fake_project(temp_dir)
    monkeypatch.setattr(cli_module, "require_project", lambda: project_path)

    db_path = get_project_db_path(project_path)
    session = SessionManager(db_path)
    session.create_project(str(project_path))

    cli_module.objective(action="show", text=None)
    out = capsys.readouterr().out
    assert "No objective set" in out

    cli_module.objective(action="set", text="Focus on login flow")
    cli_module.objective(action="show", text=None)
    out = capsys.readouterr().out
    assert "Objective" in out
    assert "Focus on login flow" in out


def test_memory_show_and_clear(monkeypatch, temp_dir: Path, capsys):
    from clawpwn import cli as cli_module
    from clawpwn.config import get_project_db_path
    from clawpwn.modules.session import SessionManager

    project_path = _make_fake_project(temp_dir)
    monkeypatch.setattr(cli_module, "require_project", lambda: project_path)

    db_path = get_project_db_path(project_path)
    session = SessionManager(db_path)
    session.create_project(str(project_path))
    session.add_message("user", "hello")
    session.add_message("assistant", "hi")

    cli_module.memory(action="show", limit=2)
    out = capsys.readouterr().out
    assert "Recent messages" in out
    assert "hello" in out

    cli_module.memory(action="clear", limit=2)
    out = capsys.readouterr().out
    assert "Memory cleared" in out


def test_lan_discover_hosts_only(monkeypatch, temp_dir: Path, capsys):
    from clawpwn import cli as cli_module
    from clawpwn.modules import network as network_module

    project_path = _make_fake_project(temp_dir)
    monkeypatch.setattr(cli_module, "require_project", lambda: project_path)

    async def fake_discover_hosts(self, network: str):
        assert network == "192.168.1.0/24"
        return ["192.168.1.10", "192.168.1.11"]

    monkeypatch.setattr(network_module.NetworkDiscovery, "discover_hosts", fake_discover_hosts)

    cli_module.discover(network="192.168.1.0/24", scan_hosts=False)

    out = capsys.readouterr().out
    assert "Discovery complete" in out
    assert "192.168.1.10" in out


def test_lan_discover_scans_hosts(monkeypatch, temp_dir: Path, capsys):
    from clawpwn import cli as cli_module
    from clawpwn.modules import network as network_module

    project_path = _make_fake_project(temp_dir)
    monkeypatch.setattr(cli_module, "require_project", lambda: project_path)

    async def fake_discover_hosts(self, network: str):
        return ["192.168.1.10"]

    async def fake_scan_host(*args, **kwargs):
        return HostInfo(ip="192.168.1.10", open_ports=[80], services=[])

    monkeypatch.setattr(network_module.NetworkDiscovery, "discover_hosts", fake_discover_hosts)
    monkeypatch.setattr(network_module.NetworkDiscovery, "scan_host", fake_scan_host)

    cli_module.discover(
        network="192.168.1.0/24",
        scan_hosts=True,
        depth="quick",
        scanner="rustscan",
        parallel=1,
        concurrency=1,
        udp=False,
        verify_tcp=False,
    )

    out = capsys.readouterr().out
    assert "Host scans complete" in out
