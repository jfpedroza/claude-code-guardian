"""Integration tests for configuration merger with rule factory."""

from pathlib import Path

import pytest

from ccguardian.config import (
    ConfigurationMerger,
    ConfigurationSource,
    RawConfiguration,
    SourceType,
)
from ccguardian.config.models import ConfigFile
from ccguardian.rules import DEFAULT_PRIORITY, Action, PathAccessRule, PreUseBashRule, Scope


class TestConfigFactoryIntegration:
    """Integration tests for merger with rule factory."""

    def setup_method(self):
        self.merger = ConfigurationMerger()

    def test_merger_creates_rule_objects(self):
        source = ConfigurationSource(SourceType.USER, Path("/test.yml"), True)
        config_data = ConfigFile.model_validate(
            {
                "default_rules": True,
                "rules": {
                    "security.dangerous_commands": {
                        "type": "pre_use_bash",
                        "pattern": "rm -rf|sudo rm",
                        "action": "deny",
                        "message": "Dangerous command detected",
                        "priority": 100,
                        "enabled": True,
                    },
                    "security.env_files": {
                        "type": "path_access",
                        "pattern": "**/.env*",
                        "scope": "read_write",
                        "action": "deny",
                        "message": "Access to environment files blocked",
                        "priority": 90,
                        "enabled": True,
                    },
                    "performance.git_operations": {
                        "type": "pre_use_bash",
                        "action": "ask",
                        "priority": 80,
                        "commands": [
                            {
                                "pattern": "git push$",
                                "action": "allow",
                                "message": "Standard git push allowed",
                            },
                            {
                                "pattern": "git push.*--force",
                                "action": "ask",
                                "message": "Force push confirmation",
                            },
                        ],
                        "enabled": True,
                    },
                },
            }
        )
        raw_config = RawConfiguration(source=source, data=config_data)

        result = self.merger.merge_configurations([raw_config])

        assert len(result.rules) == 3
        assert all(hasattr(rule, "evaluate") for rule in result.rules)

        assert result.rules[0].priority == 100  # security.dangerous_commands
        assert result.rules[1].priority == 90  # security.env_files
        assert result.rules[2].priority == 80  # performance.git_operations

        rule1 = result.rules[0]
        assert isinstance(rule1, PreUseBashRule)
        assert rule1.id == "security.dangerous_commands"
        assert rule1.action == Action.DENY
        assert rule1.message == "Dangerous command detected"
        assert rule1.enabled is True
        assert len(rule1.commands) == 1
        assert rule1.commands[0].pattern == "rm -rf|sudo rm"

        rule2 = result.rules[1]
        assert isinstance(rule2, PathAccessRule)
        assert rule2.id == "security.env_files"
        assert rule2.action == Action.DENY
        assert rule2.scope == Scope.READ_WRITE
        assert rule2.message == "Access to environment files blocked"
        assert len(rule2.paths) == 1
        assert rule2.paths[0].pattern == "**/.env*"

        rule3 = result.rules[2]
        assert isinstance(rule3, PreUseBashRule)
        assert rule3.id == "performance.git_operations"
        assert rule3.action == Action.ASK
        assert len(rule3.commands) == 2
        assert rule3.commands[0].pattern == "git push$"
        assert rule3.commands[0].action == Action.ALLOW
        assert rule3.commands[1].pattern == "git push.*--force"
        assert rule3.commands[1].action == Action.ASK

    def test_merger_handles_invalid_rules(self):
        # With Pydantic validation, invalid configurations fail at ConfigFile creation
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            ConfigFile.model_validate(
                {
                    "rules": {
                        "valid.rule": {
                            "type": "pre_use_bash",
                            "pattern": "test",
                            "action": "allow",
                        },
                        "invalid.missing_type": {
                            "pattern": "test",
                            "action": "deny",
                        },
                        "invalid.unknown_type": {
                            "type": "unknown_rule_type",
                            "pattern": "test",
                        },
                        "invalid.no_patterns": {
                            "type": "pre_use_bash",
                            "action": "deny",
                        },
                        "another.valid": {
                            "type": "path_access",
                            "pattern": "*.log",
                            "action": "warn",
                        },
                    }
                }
            )

    def test_merger_rule_merging_with_factory(self):
        # First config
        source1 = ConfigurationSource(SourceType.USER, Path("/user.yml"), True)
        config_data1 = ConfigFile.model_validate(
            {
                "rules": {
                    "test.rule": {
                        "type": "pre_use_bash",
                        "pattern": "original",
                        "action": "allow",
                        "priority": DEFAULT_PRIORITY,
                        "message": "Original message",
                    }
                }
            }
        )
        config1 = RawConfiguration(source=source1, data=config_data1)

        source2 = ConfigurationSource(SourceType.LOCAL, Path("/local.yml"), True)
        config_data2 = ConfigFile.model_validate(
            {
                "rules": {
                    "test.rule": {
                        "type": "pre_use_bash",  # Required for Pydantic validation
                        "pattern": "overridden",
                        "action": "deny",
                        "message": "Overridden message",
                    }
                }
            }
        )
        config2 = RawConfiguration(source=source2, data=config_data2)

        result = self.merger.merge_configurations([config1, config2])

        assert len(result.rules) == 1
        rule = result.rules[0]

        assert isinstance(rule, PreUseBashRule)
        assert rule.id == "test.rule"
        assert rule.priority == DEFAULT_PRIORITY  # From first config
        assert rule.action == Action.DENY  # Overridden
        assert rule.message == "Overridden message"  # Overridden
        assert len(rule.commands) == 1
        assert rule.commands[0].pattern == "overridden"  # Overridden

    def test_empty_configuration_creates_empty_rules(self):
        result = self.merger.merge_configurations([])

        assert result.rules == []
        assert result.default_rules is True
