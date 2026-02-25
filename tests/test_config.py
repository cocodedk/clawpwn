"""Tests for configuration management."""

from pathlib import Path

import pytest

from clawpwn import config


class TestLoadEnvFile:
    """Tests for load_env_file."""

    def test_load_env_file_missing_returns_empty(self, temp_dir: Path) -> None:
        env_path = temp_dir / ".env"
        assert not env_path.exists()
        assert config.load_env_file(env_path) == {}

    def test_load_env_file_parses_key_value(self, temp_dir: Path) -> None:
        env_path = temp_dir / ".env"
        env_path.write_text("FOO=bar\nBAZ=qux\n")
        assert config.load_env_file(env_path) == {"FOO": "bar", "BAZ": "qux"}

    def test_load_env_file_ignores_comments_and_empty(self, temp_dir: Path) -> None:
        env_path = temp_dir / ".env"
        env_path.write_text("# comment\n\nFOO=bar\n  \n# another\nBAR=baz\n")
        assert config.load_env_file(env_path) == {"FOO": "bar", "BAR": "baz"}

    def test_load_env_file_strips_quotes(self, temp_dir: Path) -> None:
        env_path = temp_dir / ".env"
        env_path.write_text("FOO=\"bar\"\nBAZ='qux'\n")
        assert config.load_env_file(env_path) == {"FOO": "bar", "BAZ": "qux"}


class TestLoadGlobalConfig:
    """Tests for load_global_config."""

    def test_load_global_config_missing_returns_empty(
        self, monkeypatch: pytest.MonkeyPatch, temp_dir: Path
    ) -> None:
        monkeypatch.setattr(Path, "home", lambda: temp_dir)
        assert config.load_global_config() == {}

    def test_load_global_config_loads_yml(
        self, monkeypatch: pytest.MonkeyPatch, temp_dir: Path
    ) -> None:
        config_dir = temp_dir / ".clawpwn"
        config_dir.mkdir()
        config_path = config_dir / "config.yml"
        config_path.write_text("ai:\n  provider: anthropic\n  model: claude-3\n")
        monkeypatch.setattr(Path, "home", lambda: temp_dir)
        result = config.load_global_config()
        assert result == {"ai": {"provider": "anthropic", "model": "claude-3"}}


class TestGetProjectStorageDir:
    """Tests for get_project_storage_dir."""

    def test_get_project_storage_dir_none_returns_none(self) -> None:
        assert config.get_project_storage_dir(None) is None

    def test_get_project_storage_dir_marker_is_dir_returns_marker(self, project_dir: Path) -> None:
        marker = project_dir / ".clawpwn"
        assert marker.is_dir()
        assert config.get_project_storage_dir(project_dir) == marker

    def test_get_project_storage_dir_marker_is_file_redirects(self, temp_dir: Path) -> None:
        project_path = temp_dir / "proj"
        project_path.mkdir()
        storage_path = temp_dir / "custom_storage"
        storage_path.mkdir()
        marker = project_path / ".clawpwn"
        marker.write_text(str(storage_path))
        assert config.get_project_storage_dir(project_path) == storage_path

    def test_get_project_storage_dir_with_clawpwn_data_dir(
        self, temp_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        project_path = temp_dir / "my_project"
        project_path.mkdir()
        data_root = temp_dir / "data_root"
        data_root.mkdir()
        monkeypatch.setenv("CLAWPWN_DATA_DIR", str(data_root))
        result = config.get_project_storage_dir(project_path)
        assert result is not None
        assert "my_project" in result.name
        assert result.parent == data_root
        monkeypatch.delenv("CLAWPWN_DATA_DIR", raising=False)


class TestEnsureProjectStorageDir:
    """Tests for ensure_project_storage_dir."""

    def test_ensure_project_storage_dir_existing_dir_returns_marker(
        self, project_dir: Path
    ) -> None:
        marker = project_dir / ".clawpwn"
        result = config.ensure_project_storage_dir(project_dir)
        assert result == marker

    def test_ensure_project_storage_dir_creates_via_data_dir(
        self, temp_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        project_path = temp_dir / "proj"
        project_path.mkdir()
        data_root = temp_dir / "data"
        data_root.mkdir()
        monkeypatch.setenv("CLAWPWN_DATA_DIR", str(data_root))
        result = config.ensure_project_storage_dir(project_path)
        assert result is not None
        assert result.exists()
        assert result.is_dir()
        monkeypatch.delenv("CLAWPWN_DATA_DIR", raising=False)


class TestGetProjectDbPath:
    """Tests for get_project_db_path."""

    def test_get_project_db_path_none_returns_none(self) -> None:
        assert config.get_project_db_path(None) is None

    def test_get_project_db_path_returns_db_under_storage(self, project_dir: Path) -> None:
        result = config.get_project_db_path(project_dir)
        assert result is not None
        assert result.name == "clawpwn.db"
        assert result.parent == project_dir / ".clawpwn"


class TestGetProjectEnvPath:
    """Tests for get_project_env_path."""

    def test_get_project_env_path_none_returns_none(self) -> None:
        assert config.get_project_env_path(None) is None

    def test_get_project_env_path_returns_env_under_storage(self, project_dir: Path) -> None:
        result = config.get_project_env_path(project_dir)
        assert result is not None
        assert result.name == ".env"
        assert result.parent == project_dir / ".clawpwn"


class TestGetConfig:
    """Tests for get_config."""

    def test_get_config_env_wins(self, monkeypatch: pytest.MonkeyPatch, project_dir: Path) -> None:
        monkeypatch.setenv("SOME_KEY", "from_env")
        assert config.get_config("SOME_KEY", project_dir, default="default") == "from_env"

    def test_get_config_project_env_used_when_env_unset(
        self, monkeypatch: pytest.MonkeyPatch, project_dir: Path
    ) -> None:
        monkeypatch.delenv("MY_KEY", raising=False)
        env_path = project_dir / ".clawpwn" / ".env"
        env_path.parent.mkdir(parents=True, exist_ok=True)
        env_path.write_text("MY_KEY=from_project\n")
        assert config.get_config("MY_KEY", project_dir, default="x") == "from_project"

    def test_get_config_global_used_when_project_missing(
        self, monkeypatch: pytest.MonkeyPatch, temp_dir: Path
    ) -> None:
        monkeypatch.delenv("GLOBAL_KEY", raising=False)
        monkeypatch.setattr(Path, "home", lambda: temp_dir)
        config_dir = temp_dir / ".clawpwn"
        config_dir.mkdir()
        (config_dir / "config.yml").write_text("GLOBAL_KEY: from_global\n")
        assert config.get_config("GLOBAL_KEY", None, default="x") == "from_global"

    def test_get_config_returns_default_when_missing(
        self, monkeypatch: pytest.MonkeyPatch, project_dir: Path
    ) -> None:
        monkeypatch.delenv("MISSING_KEY", raising=False)
        assert config.get_config("MISSING_KEY", project_dir, default="the_default") == "the_default"


class TestGetApiKey:
    """Tests for get_api_key."""

    def test_get_api_key_unified_preferred(
        self, monkeypatch: pytest.MonkeyPatch, project_dir: Path
    ) -> None:
        monkeypatch.setenv("CLAWPWN_LLM_API_KEY", "unified-key")
        assert config.get_api_key("anthropic", project_dir) == "unified-key"

    def test_get_api_key_fallback_anthropic(
        self, monkeypatch: pytest.MonkeyPatch, project_dir: Path
    ) -> None:
        monkeypatch.delenv("CLAWPWN_LLM_API_KEY", raising=False)
        monkeypatch.setenv("ANTHROPIC_API_KEY", "anthropic-key")
        assert config.get_api_key("anthropic", project_dir) == "anthropic-key"


class TestGetLlmConfig:
    """Tests for get_llm_provider, get_llm_model, get_llm_base_url."""

    def test_get_llm_provider_default(self, project_dir: Path) -> None:
        assert config.get_llm_provider(project_dir) == "anthropic"

    def test_get_llm_model_none_when_unset(self, project_dir: Path) -> None:
        assert config.get_llm_model(project_dir) is None

    def test_get_llm_base_url_none_when_unset(self, project_dir: Path) -> None:
        assert config.get_llm_base_url(project_dir) is None


class TestLoadProjectConfig:
    """Tests for load_project_config with explicit project_dir."""

    def test_load_project_config_with_dir_loads_env(self, project_dir: Path) -> None:
        env_path = project_dir / ".clawpwn" / ".env"
        env_path.parent.mkdir(parents=True, exist_ok=True)
        env_path.write_text("FOO=bar\n")
        result = config.load_project_config(project_dir)
        assert result == {"FOO": "bar"}


class TestCreateProjectConfigTemplate:
    """Tests for create_project_config_template."""

    def test_create_project_config_template_creates_env(
        self, temp_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        project_path = temp_dir / "proj"
        project_path.mkdir()
        data_root = temp_dir / "data"
        data_root.mkdir()
        monkeypatch.setenv("CLAWPWN_DATA_DIR", str(data_root))
        try:
            path = config.create_project_config_template(project_path)
            assert path.exists()
            assert path.name == ".env"
            content = path.read_text()
            assert "CLAWPWN_LLM" in content or "API" in content
        finally:
            monkeypatch.delenv("CLAWPWN_DATA_DIR", raising=False)
