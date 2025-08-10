"""Tests for configuration merging functionality."""

from pathlib import Path

import pytest

from ccguardian.config import (
    ConfigurationMerger,
    ConfigurationSource,
    RawConfiguration,
    SourceType,
)
from ccguardian.config.models import ConfigFile


class TestConfigurationMerger:
    def setup_method(self):
        self.merger = ConfigurationMerger()

    def test_merge_empty_configurations(self):
        result = self.merger.merge_configurations([])

        assert result.sources == []
        assert result.default_rules_enabled is True
        assert result.default_rules_patterns is None
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
        assert result.default_rules_enabled is False
        assert result.default_rules_patterns is None

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
        assert result.default_rules_enabled is False  # User config overrides
        assert result.default_rules_patterns is None

    def test_process_default_rules_true(self):
        enabled, patterns = self.merger._process_default_rules(True)
        assert enabled is True
        assert patterns is None

    def test_process_default_rules_false(self):
        enabled, patterns = self.merger._process_default_rules(False)
        assert enabled is False
        assert patterns is None

    def test_process_default_rules_patterns(self):
        enabled, patterns = self.merger._process_default_rules(["security.*", "performance.*"])
        assert enabled is True
        assert patterns == ["security.*", "performance.*"]

    def test_process_default_rules_invalid(self):
        # With Pydantic validation, the method handles invalid input gracefully
        # by falling back to default behavior
        enabled, patterns = self.merger._process_default_rules("invalid")
        assert enabled is True  # Falls back to default
        assert patterns is None

    def test_should_include_default_rule_disabled(self):
        assert not self.merger._should_include_default_rule("security.test", False, None)
        assert not self.merger._should_include_default_rule(
            "security.test", False, ["security.*"]
        )

    def test_should_include_default_rule_all_enabled(self):
        assert self.merger._should_include_default_rule("security.test", True, None)
        assert self.merger._should_include_default_rule("performance.test", True, None)

    def test_should_include_default_rule_pattern_matching(self):
        patterns = ["security.*", "performance.grep*"]

        # Should match
        assert self.merger._should_include_default_rule("security.dangerous", True, patterns)
        assert self.merger._should_include_default_rule(
            "performance.grep_suggestion", True, patterns
        )

        # Should not match
        assert not self.merger._should_include_default_rule("debug.logging", True, patterns)
        assert not self.merger._should_include_default_rule("performance.find", True, patterns)

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

        result = self.merger._merge_rules_by_id([raw_config], True, None)

        assert len(result) == 2
        assert "test.rule1" in result
        assert "test.rule2" in result
        assert result["test.rule1"]["type"] == "pre_use_bash"
        # Pattern has been converted to commands list by Pydantic
        assert "commands" in result["test.rule1"]
        assert result["test.rule1"]["commands"][0]["pattern"] == "test1"
        # Pattern has been converted to paths list by Pydantic
        assert "paths" in result["test.rule2"]
        assert result["test.rule2"]["paths"][0]["pattern"] == "*.env"

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

        result = self.merger._merge_rules_by_id([config1, config2], True, None)

        assert len(result) == 1
        assert "test.rule" in result
        rule = result["test.rule"]
        assert rule["type"] == "pre_use_bash"  # From first config
        assert (
            rule["commands"][0]["pattern"] == "overridden"
        )  # Overridden (converted to commands)
        assert rule["action"] == "deny"  # Overridden (string value)
        assert rule["priority"] == 10  # From first config
        assert rule["message"] == "Blocked by local config"  # Added

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
                        "type": "path_access",  # Different type for same rule ID
                        "pattern": "*.env",
                        "action": "deny",
                    }
                }
            }
        )
        config2 = RawConfiguration(source=source2, data=config_data2)

        # With Pydantic validation, type consistency is handled differently
        # The merger now accepts valid rule configs and merges them
        result = self.merger._merge_rules_by_id([config1, config2], True, None)
        # The later config (config2) should override the earlier one
        assert result["test.rule"]["type"] == "path_access"

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
        result = self.merger._merge_rules_by_id(
            [default_config], True, ["security.*", "performance.*"]
        )

        assert len(result) == 2
        assert "security.dangerous" in result
        assert "performance.grep" in result
        assert "debug.logging" not in result

    def test_merge_rules_invalid_data(self):
        # With Pydantic validation, invalid data fails at ConfigFile creation
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            ConfigFile.model_validate(
                {
                    "rules": {
                        "valid.rule": {"type": "pre_use_bash", "pattern": "test"},
                        "invalid.rule": "not a dictionary",  # Invalid
                        "another.valid": {"type": "path_access", "pattern": "*.env"},
                    }
                }
            )

    def test_merge_rules_invalid_rules_section(self):
        # With Pydantic validation, invalid rules section fails at ConfigFile creation
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            ConfigFile.model_validate(
                {
                    "rules": "not a dictionary"  # Invalid rules section
                }
            )
