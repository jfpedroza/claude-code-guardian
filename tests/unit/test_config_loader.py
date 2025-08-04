"""Tests for configuration loading functionality."""

import os
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

import yaml

from ccguardian.config.loader import ConfigurationLoader
from ccguardian.config.types import ConfigurationSource, SourceType


class TestConfigurationLoader:
    def setup_method(self):
        self.loader = ConfigurationLoader()

    def test_find_default_config(self):
        source = self.loader.find_default_config()

        assert source.source_type == SourceType.DEFAULT
        assert source.path.name == "default.yml"
        assert source.path.parent.name == "config"
        assert source.exists

    @patch.dict(os.environ, {}, clear=True)
    def test_find_user_config_default_location(self):
        source = self.loader.find_user_config()

        assert source.source_type == SourceType.USER
        expected_path = Path.home() / ".config" / "claude-code-guardian" / "config.yml"
        assert source.path == expected_path
        assert source.exists == expected_path.exists()

    @patch.dict(os.environ, {"CLAUDE_CODE_GUARDIAN_CONFIG": "/custom/config/path"}, clear=True)
    def test_find_user_config_environment_override(self):
        source = self.loader.find_user_config()

        assert source.source_type == SourceType.USER
        expected_path = Path("/custom/config/path") / "config.yml"
        assert source.path == expected_path
        assert source.exists == expected_path.exists()

    @patch.dict(os.environ, {}, clear=True)
    def test_find_project_configs_not_found_cwd(self):
        """Test finding project configs when .claude/guardian doesn't exist (using cwd)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("ccguardian.config.loader.Path.cwd", return_value=Path(tmpdir)):
                shared, local = self.loader.find_project_configs()

                assert shared.source_type == SourceType.SHARED
                assert local.source_type == SourceType.LOCAL
                assert not shared.exists
                assert not local.exists

                expected_dir = Path(tmpdir) / ".claude" / "guardian"
                assert shared.path == expected_dir / "config.yml"
                assert local.path == expected_dir / "config.local.yml"

    @patch.dict(os.environ, {"CLAUDE_PROJECT_DIR": "/project/root"}, clear=True)
    def test_find_project_configs_not_found_env_var(self):
        """Test finding project configs using CLAUDE_PROJECT_DIR when .claude/guardian doesn't exist."""
        shared, local = self.loader.find_project_configs()

        assert shared.source_type == SourceType.SHARED
        assert local.source_type == SourceType.LOCAL
        assert not shared.exists
        assert not local.exists

        expected_dir = Path("/project/root") / ".claude" / "guardian"
        assert shared.path == expected_dir / "config.yml"
        assert local.path == expected_dir / "config.local.yml"

    def test_find_project_configs_found_env_var(self):
        """Test finding project configs using CLAUDE_PROJECT_DIR when .claude/guardian exists."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create .claude/guardian directory structure
            guardian_dir = Path(tmpdir) / ".claude" / "guardian"
            guardian_dir.mkdir(parents=True)

            # Create config files
            shared_path = guardian_dir / "config.yml"
            local_path = guardian_dir / "config.local.yml"
            shared_path.write_text("# shared config")
            local_path.write_text("# local config")

            with patch.dict(os.environ, {"CLAUDE_PROJECT_DIR": tmpdir}, clear=True):
                shared, local = self.loader.find_project_configs()

                assert shared.exists
                assert local.exists
                assert shared.path == shared_path
                assert local.path == local_path

    def test_discover_all_sources(self):
        sources = self.loader.discover_all_sources()

        assert len(sources) == 4
        assert sources[0].source_type == SourceType.DEFAULT
        assert sources[1].source_type == SourceType.USER
        assert sources[2].source_type == SourceType.SHARED
        assert sources[3].source_type == SourceType.LOCAL

    def test_load_yaml_file_success(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            yaml.dump({"test": "data", "number": 42}, f)
            temp_path = Path(f.name)

        try:
            source = ConfigurationSource(source_type=SourceType.USER, path=temp_path, exists=True)

            result = self.loader.load_yaml_file(source)

            assert result is not None
            assert result.source == source
            assert result.data == {"test": "data", "number": 42}
        finally:
            temp_path.unlink()

    def test_load_yaml_file_not_exists(self):
        source = ConfigurationSource(
            source_type=SourceType.USER, path=Path("/nonexistent/config.yml"), exists=False
        )

        result = self.loader.load_yaml_file(source)
        assert result is None

    def test_load_yaml_file_empty(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            f.write("")  # Empty file
            temp_path = Path(f.name)

        try:
            source = ConfigurationSource(source_type=SourceType.USER, path=temp_path, exists=True)

            result = self.loader.load_yaml_file(source)
            assert result is None
        finally:
            temp_path.unlink()

    def test_load_yaml_file_invalid_yaml(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            f.write("invalid: yaml: content: [unclosed")
            temp_path = Path(f.name)

        try:
            source = ConfigurationSource(source_type=SourceType.USER, path=temp_path, exists=True)

            result = self.loader.load_yaml_file(source)
            assert result is None
        finally:
            temp_path.unlink()

    def test_load_yaml_file_not_dict(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            yaml.dump(["list", "instead", "of", "dict"], f)
            temp_path = Path(f.name)

        try:
            source = ConfigurationSource(source_type=SourceType.USER, path=temp_path, exists=True)

            result = self.loader.load_yaml_file(source)
            assert result is None
        finally:
            temp_path.unlink()

    def test_load_all_configurations(self):
        with patch.object(self.loader, "discover_all_sources") as mock_discover:
            with patch.object(self.loader, "load_yaml_file") as mock_load:
                # Mock sources
                sources = [
                    ConfigurationSource(SourceType.DEFAULT, Path("/default.yml"), True),
                    ConfigurationSource(SourceType.USER, Path("/user.yml"), False),
                    ConfigurationSource(SourceType.SHARED, Path("/shared.yml"), True),
                ]
                mock_discover.return_value = sources

                # Mock loading - only return configs for existing files
                def mock_load_side_effect(source):
                    if source.exists:
                        return Mock(source=source, data={"test": source.source_type.value})
                    return None

                mock_load.side_effect = mock_load_side_effect

                result = self.loader.load_all_configurations()

                # Should only get configs for existing files
                assert len(result) == 2
                assert result[0].source.source_type == SourceType.DEFAULT
                assert result[1].source.source_type == SourceType.SHARED
