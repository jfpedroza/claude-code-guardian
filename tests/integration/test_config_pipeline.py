"""Integration test for full configuration loading and merging pipeline."""

import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from ccguardian.config import (
    ConfigFile,
    ConfigurationLoader,
    ConfigurationManager,
    ConfigurationMerger,
    ConfigurationSource,
    ConfigValidationError,
    RawConfiguration,
    SourceType,
)
from ccguardian.rules import Action, PathAccessRule, PreUseBashRule, Scope


def _patch_env_single(config_dir, project_dir):
    """Helper for the common pattern of patching both environment variables."""
    return patch.dict(
        os.environ,
        {"CLAUDE_CODE_GUARDIAN_CONFIG": str(config_dir), "CLAUDE_PROJECT_DIR": str(project_dir)},
    )


def _patch_env_separate(user_dir, project_dir):
    """Helper for patching environment variables separately (for use with other patches)."""
    return (
        patch.dict(
            "os.environ",
            {"CLAUDE_CODE_GUARDIAN_CONFIG": str(user_dir)},
            clear=False,
        ),
        patch.dict("os.environ", {"CLAUDE_PROJECT_DIR": str(project_dir)}, clear=False),
    )


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
                        "action": "deny",
                        "message": "Use 'rg' (ripgrep) instead of 'grep'",
                        "priority": 50,
                        "enabled": True,
                    },
                    "performance.find_suggestion": {
                        "type": "pre_use_bash",
                        "pattern": r"^find\s+\S+\s+-name\b",
                        "action": "warn",
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
            env_patch1, env_patch2 = _patch_env_separate(user_config_dir, project_dir)
            with (
                patch.object(self.loader, "find_default_config") as mock_default,
                env_patch1,
                env_patch2,
            ):
                default_source = ConfigurationSource(
                    SourceType.DEFAULT, Path("/mock/default.yml"), True
                )
                mock_default.return_value = default_source
                with patch.object(self.loader, "load_yaml_file") as mock_load:

                    def mock_load_side_effect(source):
                        if source.source_type == SourceType.DEFAULT:
                            config_file = ConfigFile.model_validate(default_config)
                            return RawConfiguration(source=source, data=config_file)
                        return ConfigurationLoader.load_yaml_file(self.loader, source)

                    mock_load.side_effect = mock_load_side_effect
                    raw_configs = self.loader.load_all_configurations()
                    assert len(raw_configs) == 4
                    assert raw_configs[0].source.source_type == SourceType.DEFAULT
                    assert raw_configs[1].source.source_type == SourceType.USER
                    assert raw_configs[2].source.source_type == SourceType.SHARED
                    assert raw_configs[3].source.source_type == SourceType.LOCAL
                    merged_config = self.merger.merge_configurations(raw_configs)
                    assert merged_config.default_rules == ["performance.*"]
                    assert len(merged_config.sources) == 4
                    assert len(merged_config.rules) == 5

                    # Find specific rules and validate their properties
                    rule_map = {rule.id: rule for rule in merged_config.rules}

                    # Validate security.dangerous_command rule (overridden in shared config)
                    dangerous_rule = rule_map["security.dangerous_command"]
                    assert isinstance(dangerous_rule, PreUseBashRule)
                    assert dangerous_rule.action == Action.WARN  # Overridden from deny to warn
                    assert dangerous_rule.message == "Dangerous command - proceed with caution"
                    assert dangerous_rule.priority == 100  # From user config
                    assert dangerous_rule.enabled is True
                    assert len(dangerous_rule.commands) == 1
                    assert dangerous_rule.commands[0].pattern == "rm -rf|sudo rm"

                    # Validate project.specific_rule (PathAccessRule)
                    env_rule = rule_map["project.specific_rule"]
                    assert isinstance(env_rule, PathAccessRule)
                    assert env_rule.action == Action.DENY
                    assert env_rule.scope == Scope.READ_WRITE
                    assert env_rule.message == "Access to environment files blocked"
                    assert env_rule.priority == 80
                    assert env_rule.enabled is True
                    assert len(env_rule.paths) == 1
                    assert env_rule.paths[0].pattern == "**/.env*"

                    # Validate local.custom_rule (local override)
                    local_rule = rule_map["local.custom_rule"]
                    assert isinstance(local_rule, PreUseBashRule)
                    assert local_rule.action == Action.DENY
                    assert local_rule.message == "Internal API calls blocked in this project"
                    assert local_rule.priority == 90
                    assert local_rule.enabled is True
                    assert len(local_rule.commands) == 1
                    assert local_rule.commands[0].pattern == "curl.*internal"

                    # Validate performance.find_suggestion (disabled locally)
                    find_rule = rule_map["performance.find_suggestion"]
                    assert isinstance(find_rule, PreUseBashRule)
                    assert find_rule.enabled is False  # Disabled in local config
                    assert find_rule.priority == 50  # From default config

                    # Verify rules are sorted by priority (highest first)
                    priorities = [rule.priority for rule in merged_config.rules]
                    assert priorities == sorted(priorities, reverse=True)

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

            with _patch_env_single(user_config_dir, project_dir):
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

            with _patch_env_single(user_config_dir, project_dir):
                with pytest.raises(ConfigValidationError, match="Invalid YAML syntax"):
                    self.loader.load_all_configurations()


class TestConfigurationManagerIntegration:
    """Integration tests for ConfigurationManager end-to-end functionality."""

    def test_load_configuration_with_default_only(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            user_dir = temp_path / "user_config"
            project_dir = temp_path / "project"

            user_dir.mkdir()
            project_dir.mkdir()

            with _patch_env_single(user_dir, project_dir):
                manager = ConfigurationManager()
                config = manager.load_configuration()
                assert config.total_rules > 0
                assert len(config.active_rules) > 0
                assert config.default_rules == ["security.*"]
                source_types = [source.source_type for source in config.sources]
                assert SourceType.DEFAULT in source_types

    def test_load_configuration_with_user_config(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            project_dir = Path(temp_dir) / "project"
            project_dir.mkdir()
            with _patch_env_single(temp_dir, project_dir):
                user_config_path = Path(temp_dir) / "config.yml"
                user_config_path.write_text("""
default_rules: true
rules:
  custom.test_rule:
    type: pre_use_bash
    pattern: "test_command"
    action: warn
    message: "Custom test rule"
    priority: 100
    enabled: true
""")

                manager = ConfigurationManager()
                config = manager.load_configuration()
                rule_ids = [rule.id for rule in config.rules]
                assert "custom.test_rule" in rule_ids
                custom_rule = next(rule for rule in config.rules if rule.id == "custom.test_rule")
                assert isinstance(custom_rule, PreUseBashRule)
                assert custom_rule.action == Action.WARN
                assert custom_rule.priority == 100

    def test_load_configuration_with_project_configs(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            user_dir = Path(temp_dir) / "user_config"
            user_dir.mkdir()
            with _patch_env_single(user_dir, temp_dir):
                guardian_dir = Path(temp_dir) / ".claude" / "guardian"
                guardian_dir.mkdir(parents=True)
                shared_config = guardian_dir / "config.yml"
                shared_config.write_text("""
default_rules: true
rules:
  project.shared_rule:
    type: pre_use_bash
    pattern: "shared_command"
    action: ask
    message: "Shared project rule"
    priority: 80
    enabled: true
""")
                local_config = guardian_dir / "config.local.yml"
                local_config.write_text("""
rules:
  project.shared_rule:
    action: deny
    message: "Overridden in local config"
  project.local_rule:
    type: pre_use_bash
    pattern: "local_command"
    action: allow
    message: "Local-only rule"
    priority: 90
    enabled: true
""")

                manager = ConfigurationManager()
                config = manager.load_configuration()
                rule_ids = [rule.id for rule in config.rules]
                assert "project.shared_rule" in rule_ids
                assert "project.local_rule" in rule_ids
                shared_rule = next(
                    rule for rule in config.rules if rule.id == "project.shared_rule"
                )
                assert shared_rule.action == Action.DENY
                assert shared_rule.message == "Overridden in local config"
                local_rule = next(
                    rule for rule in config.rules if rule.id == "project.local_rule"
                )
                assert local_rule.action == Action.ALLOW
                assert local_rule.priority == 90

    def test_disabled_rules_included_in_configuration(self):
        """Test that disabled rules are included in configuration but marked as disabled."""
        with tempfile.TemporaryDirectory() as temp_dir:
            project_dir = Path(temp_dir) / "project"
            project_dir.mkdir()

            with _patch_env_single(temp_dir, project_dir):
                user_config_path = Path(temp_dir) / "config.yml"
                user_config_path.write_text("""
default_rules: true
rules:
  disabled.rule:
    type: pre_use_bash
    pattern: "disabled_command"
    action: deny
    message: "This rule is disabled"
    priority: 60
    enabled: false
""")

                manager = ConfigurationManager()
                config = manager.load_configuration()
                rule_ids = [rule.id for rule in config.rules]
                assert "disabled.rule" in rule_ids
                disabled_rule = next(rule for rule in config.rules if rule.id == "disabled.rule")
                assert not disabled_rule.enabled

    def test_configuration_merging_hierarchy(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with _patch_env_single(temp_dir, temp_dir):
                user_config_path = Path(temp_dir) / "config.yml"
                user_config_path.write_text("""
default_rules: true
rules:
  hierarchy.test:
    type: pre_use_bash
    pattern: "test"
    action: warn
    message: "User level"
    priority: 50
    enabled: true
  hierarchy.path_test:
    type: path_access
    pattern: "*.log"
    scope: read
    action: allow
    message: "User level path access"
    priority: 60
    enabled: true
  hierarchy.commands_test:
    type: pre_use_bash
    action: ask
    priority: 70
    enabled: true
    commands:
      - pattern: "git commit"
        action: allow
        message: "Git commit allowed"
      - pattern: "git push.*--force"
        action: ask
        message: "Force push confirmation"
""")
                guardian_dir = Path(temp_dir) / ".claude" / "guardian"
                guardian_dir.mkdir(parents=True)

                shared_config = guardian_dir / "config.yml"
                shared_config.write_text("""
rules:
  hierarchy.test:
    action: ask
    message: "Shared level"
  hierarchy.path_test:
    scope: write
    message: "Shared level path access"
""")

                local_config = guardian_dir / "config.local.yml"
                local_config.write_text("""
rules:
  hierarchy.test:
    action: deny
    message: "Local level - highest priority"
  hierarchy.path_test:
    action: deny
    message: "Local level - path blocked"
  hierarchy.commands_test:
    action: deny
    message: "Local level - commands blocked"
""")

                manager = ConfigurationManager()
                config = manager.load_configuration()

                rule_map = {rule.id: rule for rule in config.rules}

                # Test hierarchy.test (PreUseBashRule with pattern)
                test_rule = rule_map["hierarchy.test"]
                assert isinstance(test_rule, PreUseBashRule)
                assert test_rule.action == Action.DENY  # Local override
                assert test_rule.message == "Local level - highest priority"  # Local override
                assert test_rule.priority == 50  # From user config (preserved)
                assert test_rule.enabled is True  # From user config (preserved)
                assert len(test_rule.commands) == 1
                assert test_rule.commands[0].pattern == "test"  # From user config (preserved)

                # Test hierarchy.path_test (PathAccessRule)
                path_rule = rule_map["hierarchy.path_test"]
                assert isinstance(path_rule, PathAccessRule)
                assert path_rule.action == Action.DENY  # Local override
                assert path_rule.message == "Local level - path blocked"  # Local override
                assert path_rule.scope == Scope.WRITE  # Shared override from READ
                assert path_rule.priority == 60  # From user config (preserved)
                assert path_rule.enabled is True  # From user config (preserved)
                assert len(path_rule.paths) == 1
                assert path_rule.paths[0].pattern == "*.log"  # From user config (preserved)

                # Test hierarchy.commands_test (PreUseBashRule with commands list)
                commands_rule = rule_map["hierarchy.commands_test"]
                assert isinstance(commands_rule, PreUseBashRule)
                assert commands_rule.action == Action.DENY  # Local override
                assert commands_rule.message == "Local level - commands blocked"  # Local override
                assert commands_rule.priority == 70  # From user config (preserved)
                assert commands_rule.enabled is True  # From user config (preserved)
                assert len(commands_rule.commands) == 2  # From user config (preserved)
                assert commands_rule.commands[0].pattern == "git commit"
                assert commands_rule.commands[0].action == Action.ALLOW
                assert commands_rule.commands[1].pattern == "git push.*--force"
                assert commands_rule.commands[1].action == Action.ASK
