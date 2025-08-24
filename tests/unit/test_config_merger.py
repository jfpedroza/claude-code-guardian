"""Tests for configuration merging functionality."""

from pathlib import Path

import pytest

from ccguardian.config import (
    ConfigFile,
    ConfigurationMerger,
    ConfigurationSource,
    ConfigValidationError,
    RawConfiguration,
    SourceType,
)
from ccguardian.rules import DEFAULT_PRIORITY, PathAccessRule, PreUseBashRule


class TestConfigurationMerger:
    def setup_method(self):
        self.merger = ConfigurationMerger()

    def test_merge_empty_configurations(self):
        result = self.merger.merge_configurations([])

        assert result.sources == []
        assert result.default_rules is True
        assert result.rules == []

    def test_merge_single_configuration(self):
        source = ConfigurationSource(SourceType.USER, Path("/user.yml"), True)
        config_data = ConfigFile.model_validate(
            {
                "default_rules": False,
                "rules": {
                    "test.rule": {
                        "type": "pre_use_bash",
                        "pattern": "test",
                        "action": "deny",
                        "enabled": True,
                    }
                },
            }
        )
        raw_config = RawConfiguration(source=source, data=config_data)

        result = self.merger.merge_configurations([raw_config])

        assert len(result.sources) == 1
        assert result.sources[0] == source
        assert result.default_rules is False

        assert len(result.rules) == 1
        rule = result.rules[0]
        assert isinstance(rule, PreUseBashRule)
        assert rule.id == "test.rule"
        assert rule.action.value == "deny"
        assert rule.enabled is True

    def test_merge_multiple_configurations_hierarchy(self):
        """Test configuration merging with hierarchy, rule creation, and priority sorting."""
        # Default config with low-priority rules
        default_source = ConfigurationSource(SourceType.DEFAULT, Path("/default.yml"), True)
        default_config_data = ConfigFile.model_validate(
            {
                "default_rules": True,
                "rules": {
                    "default.low": {
                        "type": "pre_use_bash",
                        "pattern": "echo",
                        "action": "allow",
                        "priority": 10,
                    },
                    "security.dangerous": {
                        "type": "pre_use_bash",
                        "commands": [{"pattern": "rm -rf"}],
                        "action": "warn",
                        "priority": 90,
                    },
                },
            }
        )
        default_config = RawConfiguration(source=default_source, data=default_config_data)

        # User config with mixed priorities and partial overrides
        user_source = ConfigurationSource(SourceType.USER, Path("/user.yml"), True)
        user_config_data = ConfigFile.model_validate(
            {
                "default_rules": ["security.*"],  # Only include security rules from defaults
                "rules": {
                    "rule.a": {"type": "path_access", "pattern": "*.env", "priority": 100},
                    "rule.c": {
                        "type": "pre_use_bash",
                        "commands": [{"pattern": "git"}],
                        "priority": DEFAULT_PRIORITY,
                    },
                    # Partial override of default rule - upgrade priority and change action
                    "security.dangerous": {
                        "action": "deny",
                        "priority": 100,
                    },
                },
            }
        )
        user_config = RawConfiguration(source=user_source, data=user_config_data)

        # Local config adds more rules
        local_source = ConfigurationSource(SourceType.LOCAL, Path("./.config.yml"), True)
        local_config_data = ConfigFile.model_validate(
            {
                "rules": {
                    "rule.b": {
                        "type": "pre_use_bash",
                        "commands": [{"pattern": "cat"}],
                        "priority": DEFAULT_PRIORITY,
                    },
                    "security.env_files": {
                        "type": "path_access",
                        "paths": [{"pattern": "**/.env*"}],
                        "action": "deny",
                        "priority": 80,
                    },
                }
            }
        )
        local_config = RawConfiguration(source=local_source, data=local_config_data)

        result = self.merger.merge_configurations([default_config, user_config, local_config])

        assert len(result.sources) == 3
        assert result.default_rules == ["security.*"]  # From user config

        assert len(result.rules) == 5

        assert result.rules[0].id == "rule.a"
        assert result.rules[0].priority == 100
        assert isinstance(result.rules[0], PathAccessRule)

        assert result.rules[1].id == "security.dangerous"
        assert result.rules[1].priority == 100  # Upgraded from 90
        assert result.rules[1].action.value == "deny"  # Changed from "warn"
        assert isinstance(result.rules[1], PreUseBashRule)

        assert result.rules[2].id == "security.env_files"
        assert result.rules[2].priority == 80
        assert isinstance(result.rules[2], PathAccessRule)

        assert result.rules[3].id == "rule.b"
        assert result.rules[3].priority == DEFAULT_PRIORITY
        assert isinstance(result.rules[3], PreUseBashRule)

        assert result.rules[4].id == "rule.c"
        assert result.rules[4].priority == DEFAULT_PRIORITY
        assert isinstance(result.rules[4], PreUseBashRule)

    def test_should_include_default_rule_disabled(self):
        assert not self.merger._should_include_default_rule("security.test", False)

    def test_should_include_default_rule_all_enabled(self):
        assert self.merger._should_include_default_rule("security.test", True)
        assert self.merger._should_include_default_rule("performance.test", True)

    def test_should_include_default_rule_pattern_matching(self):
        patterns = ["security.*", "performance.grep*"]

        # Should match
        assert self.merger._should_include_default_rule("security.dangerous", patterns)
        assert self.merger._should_include_default_rule("performance.grep_suggestion", patterns)

        # Should not match
        assert not self.merger._should_include_default_rule("debug.logging", patterns)
        assert not self.merger._should_include_default_rule("performance.find", patterns)

    def test_merge_rules_by_id_simple(self):
        source = ConfigurationSource(SourceType.USER, Path("/user.yml"), True)
        config_data = ConfigFile.model_validate(
            {
                "rules": {
                    "test.rule1": {"type": "pre_use_bash", "pattern": "test1", "action": "allow"},
                    "test.rule2": {"type": "path_access", "pattern": "*.env", "action": "deny"},
                }
            }
        )
        raw_config = RawConfiguration(source=source, data=config_data)

        result = self.merger._merge_rules_by_id([raw_config], True)

        assert len(result) == 2
        assert "test.rule1" in result
        assert "test.rule2" in result

        rule1 = result["test.rule1"]
        assert rule1.type == "pre_use_bash"
        # Pattern has been converted to commands list by Pydantic
        assert len(rule1.commands) == 1
        assert rule1.commands[0].pattern == "test1"

        rule2 = result["test.rule2"]
        assert rule2.type == "path_access"
        # Pattern has been converted to paths list by Pydantic
        assert len(rule2.paths) == 1
        assert rule2.paths[0].pattern == "*.env"

    def test_merge_rules_by_id_override(self):
        # First config
        source1 = ConfigurationSource(SourceType.USER, Path("/user.yml"), True)
        config_data1 = ConfigFile.model_validate(
            {
                "rules": {
                    "test.rule": {
                        "type": "pre_use_bash",
                        "pattern": "original",
                        "action": "allow",
                        "priority": 10,
                    }
                }
            }
        )
        config1 = RawConfiguration(source=source1, data=config_data1)

        # Second config provides partial overrides (no type field = partial merge)
        source2 = ConfigurationSource(SourceType.LOCAL, Path("/local.yml"), True)
        config_data2 = ConfigFile.model_validate(
            {
                "rules": {
                    "test.rule": {
                        # No type field = partial merge
                        "pattern": "overridden",
                        "action": "deny",
                        "message": "Blocked by local config",
                    }
                }
            }
        )
        config2 = RawConfiguration(source=source2, data=config_data2)

        result = self.merger._merge_rules_by_id([config1, config2], True)

        assert len(result) == 1
        assert "test.rule" in result
        rule = result["test.rule"]

        assert rule.type == "pre_use_bash"  # From first config
        assert rule.commands[0].pattern == "overridden"  # Overridden (converted to commands)
        assert rule.action.value == "deny"  # Overridden (enum value)
        assert rule.priority == 10  # From first config (preserved during merge)
        assert rule.message == "Blocked by local config"  # Added

    def test_merge_rules_type_protection(self):
        # First config sets type
        source1 = ConfigurationSource(SourceType.USER, Path("/user.yml"), True)
        config_data1 = ConfigFile.model_validate(
            {"rules": {"test.rule": {"type": "pre_use_bash", "pattern": "test"}}}
        )
        config1 = RawConfiguration(source=source1, data=config_data1)

        # Second config with different type for same rule ID
        source2 = ConfigurationSource(SourceType.LOCAL, Path("/local.yml"), True)
        config_data2 = ConfigFile.model_validate(
            {
                "rules": {
                    "test.rule": {
                        "type": "path_access",  # Attempt to change type
                        "pattern": ".env*",
                        "action": "deny",
                    }
                }
            }
        )
        config2 = RawConfiguration(source=source2, data=config_data2)

        with pytest.raises(ConfigValidationError) as exc_info:
            self.merger._merge_rules_by_id([config1, config2], True)

        assert "Cannot change rule type from 'pre_use_bash' to 'path_access'" in str(
            exc_info.value
        )
        assert "test.rule" in str(exc_info.value)

    def test_merge_rules_default_filtering(self):
        # Default config with multiple rules
        default_source = ConfigurationSource(SourceType.DEFAULT, Path("/default.yml"), True)
        config_data = ConfigFile.model_validate(
            {
                "rules": {
                    "security.dangerous": {"type": "pre_use_bash", "pattern": "rm -rf"},
                    "performance.grep": {"type": "pre_use_bash", "pattern": "grep"},
                    "debug.logging": {"type": "path_access", "pattern": "*.log"},
                }
            }
        )
        default_config = RawConfiguration(source=default_source, data=config_data)

        # Test with patterns filtering
        result = self.merger._merge_rules_by_id([default_config], ["security.*", "performance.*"])

        assert len(result) == 2
        assert "security.dangerous" in result
        assert "performance.grep" in result
        assert "debug.logging" not in result
