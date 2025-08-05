"""Integration test for full configuration loading and merging pipeline."""

import tempfile
from pathlib import Path
from unittest.mock import patch

import yaml

from ccguardian.config.loader import ConfigurationLoader
from ccguardian.config.merger import ConfigurationMerger
from ccguardian.config.types import SourceType


class TestConfigurationPipeline:
    """Integration tests for configuration loading and merging pipeline."""

    def setup_method(self):
        self.loader = ConfigurationLoader()
        self.merger = ConfigurationMerger()

    def test_full_pipeline_with_temporary_configs(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            default_config = {
                "default_rules": True,
                "rules": {
                    "performance.grep_suggestion": {
                        "type": "pre_use_bash",
                        "pattern": r"^grep\b(?!.*\|)",
                        "action": "suggest",
                        "message": "Use 'rg' (ripgrep) instead of 'grep'",
                        "priority": 50,
                        "enabled": True,
                    },
                    "performance.find_suggestion": {
                        "type": "pre_use_bash",
                        "pattern": r"^find\s+\S+\s+-name\b",
                        "action": "suggest",
                        "message": "Use 'rg --files | rg pattern' for better performance",
                        "priority": 50,
                        "enabled": True,
                    },
                },
            }
            user_config_dir = tmpdir / "user_config"
            user_config_dir.mkdir()
            user_config_path = user_config_dir / "config.yml"
            user_config = {
                "default_rules": ["performance.*"],  # Filter to only performance rules
                "rules": {
                    "security.dangerous_command": {
                        "type": "pre_use_bash",
                        "pattern": "rm -rf|sudo rm",
                        "action": "deny",
                        "message": "Dangerous command detected",
                        "priority": 100,
                        "enabled": True,
                    }
                },
            }
            with open(user_config_path, "w") as f:
                yaml.dump(user_config, f)

            # Create project configs
            project_dir = tmpdir / "project"
            project_dir.mkdir()
            guardian_dir = project_dir / ".claude" / "guardian"
            guardian_dir.mkdir(parents=True)
            shared_config_path = guardian_dir / "config.yml"
            shared_config = {
                "rules": {
                    "security.dangerous_command": {
                        "action": "warn",  # Override from deny to warn
                        "message": "Dangerous command - proceed with caution",
                    },
                    "project.specific_rule": {
                        "type": "path_access",
                        "pattern": "**/.env*",
                        "scope": "read_write",
                        "action": "deny",
                        "message": "Access to environment files blocked",
                        "priority": 80,
                        "enabled": True,
                    },
                }
            }
            with open(shared_config_path, "w") as f:
                yaml.dump(shared_config, f)
            local_config_path = guardian_dir / "config.local.yml"
            local_config = {
                "rules": {
                    "performance.find_suggestion": {
                        "enabled": False  # Disable this rule locally
                    },
                    "local.custom_rule": {
                        "type": "pre_use_bash",
                        "pattern": "curl.*internal",
                        "action": "deny",
                        "message": "Internal API calls blocked in this project",
                        "priority": 90,
                        "enabled": True,
                    },
                }
            }
            with open(local_config_path, "w") as f:
                yaml.dump(local_config, f)

            # Mock the loader to use our temporary configs
            with (
                patch.object(self.loader, "find_default_config") as mock_default,
                patch.dict(
                    "os.environ",
                    {"CLAUDE_CODE_GUARDIAN_CONFIG": str(user_config_dir)},
                    clear=False,
                ),
                patch.dict("os.environ", {"CLAUDE_PROJECT_DIR": str(project_dir)}, clear=False),
            ):
                # Mock default config source
                from ccguardian.config.types import (
                    ConfigurationSource,
                    RawConfiguration,
                    SourceType,
                )

                default_source = ConfigurationSource(
                    SourceType.DEFAULT, Path("/mock/default.yml"), True
                )
                mock_default.return_value = default_source
                with patch.object(self.loader, "load_yaml_file") as mock_load:

                    def mock_load_side_effect(source):
                        if source.source_type == SourceType.DEFAULT:
                            return RawConfiguration(source=source, data=default_config)
                        return ConfigurationLoader.load_yaml_file(self.loader, source)

                    mock_load.side_effect = mock_load_side_effect
                    raw_configs = self.loader.load_all_configurations()
                    assert len(raw_configs) == 4
                    assert raw_configs[0].source.source_type == SourceType.DEFAULT
                    assert raw_configs[1].source.source_type == SourceType.USER
                    assert raw_configs[2].source.source_type == SourceType.SHARED
                    assert raw_configs[3].source.source_type == SourceType.LOCAL
                    merged_config = self.merger.merge_configurations(raw_configs)
                    assert merged_config.default_rules_enabled is True
                    assert merged_config.default_rules_patterns == ["performance.*"]
                    assert len(merged_config.sources) == 4

    def test_pipeline_with_no_project_configs(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            user_config_dir = tmpdir / "user_config"
            user_config_dir.mkdir()
            user_config_path = user_config_dir / "config.yml"
            user_config = {
                "default_rules": False,
                "rules": {
                    "user.only_rule": {
                        "type": "pre_use_bash",
                        "pattern": "test",
                        "action": "allow",
                    }
                },
            }
            with open(user_config_path, "w") as f:
                yaml.dump(user_config, f)
            project_dir = tmpdir / "empty_project"
            project_dir.mkdir()

            with (
                patch.dict(
                    "os.environ",
                    {"CLAUDE_CODE_GUARDIAN_CONFIG": str(user_config_dir)},
                    clear=False,
                ),
                patch.dict("os.environ", {"CLAUDE_PROJECT_DIR": str(project_dir)}, clear=False),
            ):
                # Discover sources
                sources = self.loader.discover_all_sources()
                assert len(sources) == 4
                assert sources[0].source_type == SourceType.DEFAULT
                assert sources[1].source_type == SourceType.USER
                assert sources[2].source_type == SourceType.SHARED
                assert sources[3].source_type == SourceType.LOCAL
                assert sources[0].exists  # default config from package
                assert sources[1].exists  # user config we created
                assert not sources[2].exists  # no shared project config
                assert not sources[3].exists  # no local project config
                raw_configs = self.loader.load_all_configurations()
                assert len(raw_configs) == 2
                assert raw_configs[0].source.source_type == SourceType.DEFAULT
                assert raw_configs[1].source.source_type == SourceType.USER

    def test_pipeline_with_invalid_yaml(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            user_config_dir = tmpdir / "user_config"
            user_config_dir.mkdir()
            user_config_path = user_config_dir / "config.yml"
            with open(user_config_path, "w") as f:
                f.write("invalid: yaml: content: [unclosed")
            project_dir = tmpdir / "project"
            guardian_dir = project_dir / ".claude" / "guardian"
            guardian_dir.mkdir(parents=True)

            shared_config_path = guardian_dir / "config.yml"
            shared_config = {"rules": {"valid.rule": {"type": "pre_use_bash", "pattern": "test"}}}
            with open(shared_config_path, "w") as f:
                yaml.dump(shared_config, f)

            local_config_path = guardian_dir / "config.local.yml"
            with open(local_config_path, "w") as f:
                f.write("another: invalid: yaml: [")

            with (
                patch.dict(
                    "os.environ",
                    {"CLAUDE_CODE_GUARDIAN_CONFIG": str(user_config_dir)},
                    clear=False,
                ),
                patch.dict("os.environ", {"CLAUDE_PROJECT_DIR": str(project_dir)}, clear=False),
            ):
                # Load configurations - should handle invalid YAML gracefully
                raw_configs = self.loader.load_all_configurations()

                # Should only load valid configs (default + shared)
                assert len(raw_configs) == 2
                assert raw_configs[0].source.source_type == SourceType.DEFAULT
                assert raw_configs[1].source.source_type == SourceType.SHARED

                # Merge should work with partial configs
                merged_config = self.merger.merge_configurations(raw_configs)
                assert len(merged_config.sources) == 2
