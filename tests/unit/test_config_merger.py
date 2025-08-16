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

    def test_merge_multiple_configurations_hierarchy(self):
        # Default config
        default_source = ConfigurationSource(SourceType.DEFAULT, Path("/default.yml"), True)
        default_config_data = ConfigFile.model_validate(
            {
                "default_rules": True,
                "rules": {
                    "default.rule": {
                        "type": "pre_use_bash",
                        "pattern": "default",
                        "action": "allow",
                        "priority": 10,
                    }
                },
            }
        )
        default_config = RawConfiguration(source=default_source, data=default_config_data)

        # User config overrides
        user_source = ConfigurationSource(SourceType.USER, Path("/user.yml"), True)
        user_config_data = ConfigFile.model_validate(
            {
                "default_rules": False,
                "rules": {
                    "user.rule": {"type": "path_access", "pattern": "*.env", "action": "deny"}
                },
            }
        )
        user_config = RawConfiguration(source=user_source, data=user_config_data)

        result = self.merger.merge_configurations([default_config, user_config])

        assert len(result.sources) == 2
        assert result.default_rules is False  # User config overrides

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

        # Second config overrides
        source2 = ConfigurationSource(SourceType.LOCAL, Path("/local.yml"), True)
        config_data2 = ConfigFile.model_validate(
            {
                "rules": {
                    "test.rule": {
                        "type": "pre_use_bash",  # Required for Pydantic validation
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
        assert rule.priority == 10  # From first config
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
