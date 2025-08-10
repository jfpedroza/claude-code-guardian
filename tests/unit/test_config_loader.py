"""Tests for configuration loading functionality."""

import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest
import yaml

from ccguardian.config import (
    ConfigurationLoader,
    ConfigurationSource,
    ConfigValidationError,
    SourceType,
)


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
    def test_find_project_configs_env_var_nonexistent_dir(self):
        """Test finding project configs when CLAUDE_PROJECT_DIR points to nonexistent directory."""
        with pytest.raises(
            ConfigValidationError, match="CLAUDE_PROJECT_DIR directory does not exist"
        ):
            self.loader.find_project_configs()

    def test_find_project_configs_env_var_no_guardian_dir(self):
        """Test finding project configs when CLAUDE_PROJECT_DIR exists but .claude/guardian doesn't."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.dict(os.environ, {"CLAUDE_PROJECT_DIR": tmpdir}, clear=True):
                shared, local = self.loader.find_project_configs()

                assert shared.source_type == SourceType.SHARED
                assert local.source_type == SourceType.LOCAL
                assert not shared.exists
                assert not local.exists

                expected_dir = Path(tmpdir) / ".claude" / "guardian"
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
            yaml.dump(
                {
                    "default_rules": True,
                    "rules": {
                        "test.rule": {"type": "pre_use_bash", "pattern": "test", "enabled": True}
                    },
                },
                f,
            )
            temp_path = Path(f.name)

        try:
            source = ConfigurationSource(source_type=SourceType.USER, path=temp_path, exists=True)

            result = self.loader.load_yaml_file(source)

            assert result is not None
            assert result.source == source
            # result.data is now a ConfigFile object
            assert result.data.default_rules is True
            assert len(result.data.rules) == 1
            assert "test.rule" in result.data.rules
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

            with pytest.raises(ConfigValidationError, match="Invalid YAML syntax"):
                self.loader.load_yaml_file(source)
        finally:
            temp_path.unlink()

    def test_load_yaml_file_not_dict(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            yaml.dump(["list", "instead", "of", "dict"], f)
            temp_path = Path(f.name)

        try:
            source = ConfigurationSource(source_type=SourceType.USER, path=temp_path, exists=True)

            with pytest.raises(
                ConfigValidationError, match="Configuration file must contain a YAML object"
            ):
                self.loader.load_yaml_file(source)
        finally:
            temp_path.unlink()

    def test_load_yaml_file_invalid_rule_type(self):
        """Test Pydantic validation error for invalid rule type."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            yaml.dump(
                {
                    "rules": {
                        "test.rule": {
                            "type": "invalid_type",  # Invalid rule type
                            "pattern": "test",
                        }
                    }
                },
                f,
            )
            temp_path = Path(f.name)

        try:
            source = ConfigurationSource(source_type=SourceType.USER, path=temp_path, exists=True)

            with pytest.raises(ConfigValidationError, match="Configuration validation failed"):
                self.loader.load_yaml_file(source)
        finally:
            temp_path.unlink()

    def test_load_yaml_file_missing_required_field(self):
        """Test Pydantic validation error for missing required fields."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            yaml.dump(
                {
                    "rules": {
                        "test.rule": {
                            "type": "pre_use_bash"
                            # Missing pattern or commands
                        }
                    }
                },
                f,
            )
            temp_path = Path(f.name)

        try:
            source = ConfigurationSource(source_type=SourceType.USER, path=temp_path, exists=True)

            with pytest.raises(ConfigValidationError, match="Configuration validation failed"):
                self.loader.load_yaml_file(source)
        finally:
            temp_path.unlink()

    def test_load_yaml_file_invalid_regex_pattern(self):
        """Test Pydantic validation error for invalid regex pattern."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            yaml.dump(
                {
                    "rules": {
                        "test.rule": {
                            "type": "pre_use_bash",
                            "pattern": "[invalid",  # Invalid regex
                        }
                    }
                },
                f,
            )
            temp_path = Path(f.name)

        try:
            source = ConfigurationSource(source_type=SourceType.USER, path=temp_path, exists=True)

            with pytest.raises(ConfigValidationError, match="Configuration validation failed"):
                self.loader.load_yaml_file(source)
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

                # Mock loading - return configs with ConfigFile data for existing files, None for non-existing
                def mock_load_side_effect(source):
                    if source.exists:
                        from ccguardian.config.models import ConfigFile

                        config_file = ConfigFile(default_rules=True, rules={})
                        return Mock(source=source, data=config_file)
                    else:
                        return None

                mock_load.side_effect = mock_load_side_effect

                result = self.loader.load_all_configurations()

                # Should only get configs that exist (None configs are filtered out)
                assert len(result) == 2
                assert result[0].source.source_type == SourceType.DEFAULT
                assert result[1].source.source_type == SourceType.SHARED

    def test_validate_project_dir_valid(self, temp_config_dir):
        # Valid absolute path
        result = self.loader._validate_project_dir(str(temp_config_dir))
        assert result == temp_config_dir.resolve()

    def test_validate_project_dir_invalid_relative(self):
        with pytest.raises(ConfigValidationError, match="must be an absolute path"):
            self.loader._validate_project_dir("relative/path")

    def test_validate_project_dir_invalid_traversal(self):
        with pytest.raises(
            ConfigValidationError, match="cannot contain '\\.\\.' path components"
        ):
            self.loader._validate_project_dir("/some/path/../../../etc")

    def test_validate_project_dir_resolve_error(self):
        mock_path = MagicMock()
        mock_path.expanduser.return_value = mock_path
        mock_path.is_absolute.return_value = True
        mock_path.parts = ["/", "valid", "path"]
        mock_path.resolve.side_effect = OSError("Mock resolve error")

        with patch("ccguardian.config.loader.Path", return_value=mock_path):
            with pytest.raises(ConfigValidationError, match="Invalid CLAUDE_PROJECT_DIR path"):
                self.loader._validate_project_dir("/valid/path")

    def test_validate_project_dir_not_exists(self):
        with pytest.raises(
            ConfigValidationError, match="CLAUDE_PROJECT_DIR directory does not exist"
        ):
            self.loader._validate_project_dir("/nonexistent/directory")

    def test_validate_config_dir_valid(self, temp_config_dir):
        result = self.loader._validate_config_dir(str(temp_config_dir), "TEST_VAR")
        assert result == temp_config_dir.resolve()

    def test_validate_config_dir_invalid_relative(self):
        with pytest.raises(ConfigValidationError, match="TEST_VAR must be an absolute path"):
            self.loader._validate_config_dir("relative/path", "TEST_VAR")

    def test_validate_config_dir_invalid_traversal(self):
        with pytest.raises(
            ConfigValidationError, match="cannot contain '\\.\\.' path components"
        ):
            self.loader._validate_config_dir("/some/path/../../../etc", "TEST_VAR")
