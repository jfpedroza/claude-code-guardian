"""Test suite for Pydantic configuration models."""

import pytest
from pydantic import ValidationError

from ccguardian.config.models import (
    CommandPatternModel,
    ConfigFile,
    PathAccessRuleConfig,
    PathPatternModel,
    PreUseBashRuleConfig,
)
from ccguardian.rules import Action, Scope


class TestCommandPatternModel:
    """Tests for CommandPatternModel."""

    def test_valid_command_pattern(self):
        """Test creation of valid command pattern."""
        pattern = CommandPatternModel(
            pattern=r"git push.*--force",
            action=Action.ASK,
            message="Force push requires confirmation",
        )

        assert pattern.pattern == r"git push.*--force"
        assert pattern.action == Action.ASK
        assert pattern.message == "Force push requires confirmation"

    def test_valid_command_pattern_minimal(self):
        """Test creation with only required fields."""
        pattern = CommandPatternModel(pattern="ls")

        assert pattern.pattern == "ls"
        assert pattern.action is None
        assert pattern.message is None

    def test_invalid_regex_pattern(self):
        """Test validation of invalid regex patterns."""
        with pytest.raises(ValidationError) as exc_info:
            CommandPatternModel(pattern="[unclosed")

        errors = exc_info.value.errors()
        assert len(errors) == 1
        assert "Invalid regex pattern" in errors[0]["msg"]
        assert errors[0]["loc"] == ("pattern",)

    def test_empty_pattern(self):
        """Test validation of empty pattern."""
        with pytest.raises(ValidationError) as exc_info:
            CommandPatternModel(pattern="")

        errors = exc_info.value.errors()
        assert len(errors) == 1
        assert "Pattern must be a non-empty string" in errors[0]["msg"]

    def test_none_pattern(self):
        """Test validation of None pattern."""
        with pytest.raises(ValidationError):
            CommandPatternModel(pattern=None)


class TestPathPatternModel:
    """Tests for PathPatternModel."""

    def test_valid_path_pattern(self):
        """Test creation of valid path pattern."""
        pattern = PathPatternModel(
            pattern="**/.env*",
            scope=Scope.READ_WRITE,
            action=Action.DENY,
            message="Environment files blocked",
        )

        assert pattern.pattern == "**/.env*"
        assert pattern.scope == Scope.READ_WRITE
        assert pattern.action == Action.DENY
        assert pattern.message == "Environment files blocked"

    def test_valid_path_pattern_minimal(self):
        """Test creation with only required fields."""
        pattern = PathPatternModel(pattern="*.txt")

        assert pattern.pattern == "*.txt"
        assert pattern.scope is None
        assert pattern.action is None
        assert pattern.message is None

    def test_glob_pattern_validation_simple(self):
        """Test various valid glob patterns."""
        valid_patterns = [
            "*.txt",
            "**/*.py",
            "/etc/**",
            "config/*.yml",
            "**/secrets/**",
            "file[12].txt",
            "file?.txt",
        ]

        for pattern_str in valid_patterns:
            pattern = PathPatternModel(pattern=pattern_str)
            assert pattern.pattern == pattern_str

    def test_invalid_glob_pattern_unbalanced_brackets(self):
        """Test validation of glob patterns with unbalanced brackets."""
        invalid_patterns = [
            "[unclosed",
            "unclosed]",
            "nested[[brackets]]",
        ]

        for pattern_str in invalid_patterns:
            with pytest.raises(ValidationError) as exc_info:
                PathPatternModel(pattern=pattern_str)

            errors = exc_info.value.errors()
            assert len(errors) == 1
            assert "bracket" in errors[0]["msg"].lower()

    def test_empty_pattern(self):
        """Test validation of empty pattern."""
        with pytest.raises(ValidationError) as exc_info:
            PathPatternModel(pattern="")

        errors = exc_info.value.errors()
        assert len(errors) == 1
        assert "Pattern must be a non-empty string" in errors[0]["msg"]


class TestPreUseBashRuleConfig:
    """Tests for PreUseBashRuleConfig."""

    def test_single_pattern_format(self):
        """Test rule with single pattern (legacy format)."""
        rule = PreUseBashRuleConfig(
            type="pre_use_bash",
            pattern="git push",
            action=Action.ASK,
            enabled=True,
            priority=50,
            message="Git push requires confirmation",
        )

        assert rule.type == "pre_use_bash"
        assert rule.pattern is None  # Should be converted to commands
        assert rule.commands is not None
        assert len(rule.commands) == 1
        assert rule.commands[0].pattern == "git push"
        assert rule.commands[0].action is None  # Inherits from rule level
        assert rule.action == Action.ASK
        assert rule.enabled is True
        assert rule.priority == 50
        assert rule.message == "Git push requires confirmation"

    def test_commands_list_format(self):
        """Test rule with commands list format."""
        rule = PreUseBashRuleConfig(
            type="pre_use_bash",
            commands=[
                CommandPatternModel(pattern="git push$", action=Action.ALLOW),
                CommandPatternModel(pattern="git push.*--force", action=Action.ASK),
            ],
            action=Action.WARN,
            enabled=True,
            priority=100,
        )

        assert rule.type == "pre_use_bash"
        assert rule.pattern is None
        assert rule.commands is not None
        assert len(rule.commands) == 2
        assert rule.commands[0].pattern == "git push$"
        assert rule.commands[0].action == Action.ALLOW
        assert rule.commands[1].pattern == "git push.*--force"
        assert rule.commands[1].action == Action.ASK
        assert rule.action == Action.WARN
        assert rule.priority == 100

    def test_missing_pattern_and_commands(self):
        """Test validation when both pattern and commands are missing."""
        with pytest.raises(ValidationError) as exc_info:
            PreUseBashRuleConfig(type="pre_use_bash")

        errors = exc_info.value.errors()
        assert len(errors) == 1
        assert "requires either 'pattern' or 'commands'" in errors[0]["msg"]

    def test_both_pattern_and_commands(self):
        """Test validation when both pattern and commands are provided."""
        with pytest.raises(ValidationError) as exc_info:
            PreUseBashRuleConfig(
                type="pre_use_bash",
                pattern="git push",
                commands=[CommandPatternModel(pattern="ls")],
            )

        errors = exc_info.value.errors()
        assert len(errors) == 1
        assert "mutually exclusive" in errors[0]["msg"]

    def test_empty_commands_list(self):
        """Test validation of empty commands list."""
        with pytest.raises(ValidationError) as exc_info:
            PreUseBashRuleConfig(
                type="pre_use_bash",
                commands=[],
            )

        errors = exc_info.value.errors()
        assert len(errors) == 1
        assert "cannot be empty" in errors[0]["msg"]

    def test_invalid_regex_in_pattern(self):
        """Test validation of invalid regex in pattern field."""
        with pytest.raises(ValidationError) as exc_info:
            PreUseBashRuleConfig(
                type="pre_use_bash",
                pattern="[invalid",
            )

        errors = exc_info.value.errors()
        assert len(errors) == 1
        assert "Invalid regex pattern" in errors[0]["msg"]

    def test_negative_priority(self):
        """Test validation of negative priority."""
        with pytest.raises(ValidationError) as exc_info:
            PreUseBashRuleConfig(
                type="pre_use_bash",
                pattern="ls",
                priority=-1,
            )

        errors = exc_info.value.errors()
        assert len(errors) == 1
        assert "Priority must be non-negative" in errors[0]["msg"]

    def test_wrong_type(self):
        """Test validation of wrong rule type."""
        with pytest.raises(ValidationError) as exc_info:
            PreUseBashRuleConfig(
                type="path_access",  # Wrong type
                pattern="ls",
            )

        errors = exc_info.value.errors()
        assert len(errors) == 1
        assert "type" in errors[0]["loc"]

    def test_defaults(self):
        """Test default values."""
        rule = PreUseBashRuleConfig(
            type="pre_use_bash",
            pattern="ls",
        )

        assert rule.enabled is None
        assert rule.priority is None
        assert rule.action is None
        assert rule.message is None

    def test_pre_use_bash_rule_merge_pattern(self):
        """Test merging a pattern into an existing PreUseBashRule."""
        base_rule = PreUseBashRuleConfig(
            type="pre_use_bash", pattern="git push", enabled=True, priority=100
        )

        partial_config = {"pattern": "git pull", "action": "deny"}

        result = base_rule.merge(partial_config)

        assert isinstance(result, PreUseBashRuleConfig)
        assert result.enabled is True  # Inherited from base
        assert result.priority == 100  # Inherited from base
        assert result.action == Action.DENY  # From partial
        assert len(result.commands) == 1
        assert result.commands[0].pattern == "git pull"  # Pattern converted to commands
        assert result.pattern is None  # Pattern cleared after conversion

    def test_pre_use_bash_rule_merge_commands(self):
        """Test merging commands into an existing PreUseBashRule."""
        base_rule = PreUseBashRuleConfig(type="pre_use_bash", pattern="git push", priority=50)

        partial_config = {
            "commands": [
                {"pattern": "git clone", "action": "allow"},
                {"pattern": "git pull", "action": "ask"},
            ],
            "enabled": False,
        }

        result = base_rule.merge(partial_config)

        assert isinstance(result, PreUseBashRuleConfig)
        assert result.priority == 50  # Inherited from base
        assert result.enabled is False  # From partial
        assert len(result.commands) == 2
        assert result.commands[0].pattern == "git clone"
        assert result.commands[0].action == Action.ALLOW
        assert result.commands[1].pattern == "git pull"
        assert result.commands[1].action == Action.ASK
        assert result.pattern is None  # Pattern cleared after commands override

    def test_merge_invalid_action(self):
        """Test that merge validates action values."""
        base_rule = PreUseBashRuleConfig(type="pre_use_bash", pattern="test")

        partial_config = {"action": "invalid_action"}

        with pytest.raises(ValueError, match="Invalid action value"):
            base_rule.merge(partial_config)

    def test_merge_invalid_priority(self):
        """Test that merge validates priority values."""
        base_rule = PreUseBashRuleConfig(type="pre_use_bash", pattern="test")

        partial_config = {"priority": -1}

        with pytest.raises(ValueError, match="Priority must be a non-negative integer"):
            base_rule.merge(partial_config)

    def test_merge_invalid_commands_list(self):
        """Test that merge validates commands list structure."""
        base_rule = PreUseBashRuleConfig(type="pre_use_bash", pattern="test")

        partial_config = {"commands": "not_a_list"}

        with pytest.raises(ValueError, match="'commands' field must be a non-empty list"):
            base_rule.merge(partial_config)


class TestPathAccessRuleConfig:
    """Tests for PathAccessRuleConfig."""

    def test_single_pattern_format(self):
        """Test rule with single pattern (legacy format)."""
        rule = PathAccessRuleConfig(
            type="path_access",
            pattern="**/.env*",
            scope=Scope.READ_WRITE,
            action=Action.DENY,
            enabled=True,
            priority=60,
            message="Environment files blocked",
        )

        assert rule.type == "path_access"
        assert rule.pattern is None  # Should be converted to paths
        assert rule.paths is not None
        assert len(rule.paths) == 1
        assert rule.paths[0].pattern == "**/.env*"
        assert rule.paths[0].scope is None  # Inherits from rule level
        assert rule.scope == Scope.READ_WRITE
        assert rule.action == Action.DENY
        assert rule.enabled is True
        assert rule.priority == 60
        assert rule.message == "Environment files blocked"

    def test_paths_list_format(self):
        """Test rule with paths list format."""
        rule = PathAccessRuleConfig(
            type="path_access",
            paths=[
                PathPatternModel(pattern="**/.git/**", scope=Scope.WRITE, action=Action.WARN),
                PathPatternModel(pattern="**/secrets/**", scope=Scope.READ, action=Action.DENY),
            ],
            action=Action.ASK,
            enabled=True,
            priority=90,
        )

        assert rule.type == "path_access"
        assert rule.pattern is None
        assert rule.paths is not None
        assert len(rule.paths) == 2
        assert rule.paths[0].pattern == "**/.git/**"
        assert rule.paths[0].scope == Scope.WRITE
        assert rule.paths[0].action == Action.WARN
        assert rule.paths[1].pattern == "**/secrets/**"
        assert rule.paths[1].scope == Scope.READ
        assert rule.paths[1].action == Action.DENY
        assert rule.action == Action.ASK
        assert rule.priority == 90

    def test_missing_pattern_and_paths(self):
        """Test validation when both pattern and paths are missing."""
        with pytest.raises(ValidationError) as exc_info:
            PathAccessRuleConfig(type="path_access")

        errors = exc_info.value.errors()
        assert len(errors) == 1
        assert "requires either 'pattern' or 'paths'" in errors[0]["msg"]

    def test_both_pattern_and_paths(self):
        """Test validation when both pattern and paths are provided."""
        with pytest.raises(ValidationError) as exc_info:
            PathAccessRuleConfig(
                type="path_access",
                pattern="*.env",
                paths=[PathPatternModel(pattern="*.txt")],
            )

        errors = exc_info.value.errors()
        assert len(errors) == 1
        assert "mutually exclusive" in errors[0]["msg"]

    def test_empty_paths_list(self):
        """Test validation of empty paths list."""
        with pytest.raises(ValidationError) as exc_info:
            PathAccessRuleConfig(
                type="path_access",
                paths=[],
            )

        errors = exc_info.value.errors()
        assert len(errors) == 1
        assert "cannot be empty" in errors[0]["msg"]

    def test_invalid_glob_in_pattern(self):
        """Test validation of invalid glob in pattern field."""
        with pytest.raises(ValidationError) as exc_info:
            PathAccessRuleConfig(
                type="path_access",
                pattern="[invalid",
            )

        errors = exc_info.value.errors()
        assert len(errors) == 1
        assert "bracket" in errors[0]["msg"].lower()

    def test_wrong_type(self):
        """Test validation of wrong rule type."""
        with pytest.raises(ValidationError) as exc_info:
            PathAccessRuleConfig(
                type="pre_use_bash",  # Wrong type
                pattern="*.txt",
            )

        errors = exc_info.value.errors()
        assert len(errors) == 1
        assert "type" in errors[0]["loc"]

    def test_defaults(self):
        """Test default values."""
        rule = PathAccessRuleConfig(
            type="path_access",
            pattern="*.txt",
        )

        assert rule.enabled is None
        assert rule.priority is None
        assert rule.action is None
        assert rule.message is None
        assert rule.scope is None

    def test_path_access_rule_merge_pattern(self):
        """Test merging a pattern into an existing PathAccessRule."""
        base_rule = PathAccessRuleConfig(
            type="path_access", pattern="*.txt", scope=Scope.READ, priority=75
        )

        partial_config = {"pattern": "*.env", "action": "deny"}

        result = base_rule.merge(partial_config)

        assert isinstance(result, PathAccessRuleConfig)
        assert result.priority == 75  # Inherited from base
        assert result.scope == Scope.READ  # Inherited from base
        assert result.action == Action.DENY  # From partial
        assert len(result.paths) == 1
        assert result.paths[0].pattern == "*.env"  # Pattern converted to paths
        assert result.pattern is None  # Pattern cleared after conversion

    def test_path_access_rule_merge_scope(self):
        """Test merging scope and other fields into PathAccessRule."""
        base_rule = PathAccessRuleConfig(type="path_access", pattern="*.log", priority=25)

        partial_config = {"scope": "write", "message": "Log files are protected", "enabled": True}

        result = base_rule.merge(partial_config)

        assert isinstance(result, PathAccessRuleConfig)
        assert result.priority == 25  # Inherited from base
        assert result.scope == Scope.WRITE  # From partial
        assert result.message == "Log files are protected"  # From partial
        assert result.enabled is True  # From partial
        assert len(result.paths) == 1
        assert result.paths[0].pattern == "*.log"  # Base pattern preserved


class TestConfigFile:
    """Tests for ConfigFile model."""

    def test_valid_config_with_default_rules_bool(self):
        """Test config with default_rules as boolean."""
        config = ConfigFile(
            default_rules=True,
            rules={
                "test.rule": PreUseBashRuleConfig(
                    type="pre_use_bash",
                    pattern="ls",
                )
            },
        )

        assert config.default_rules is True
        assert len(config.rules) == 1
        assert "test.rule" in config.rules

    def test_valid_config_with_default_rules_list(self):
        """Test config with default_rules as list."""
        config = ConfigFile(
            default_rules=["security.*", "performance.*"],
            rules={},
        )

        assert config.default_rules == ["security.*", "performance.*"]
        assert len(config.rules) == 0

    def test_valid_config_with_default_rules_none(self):
        """Test config with default_rules as None."""
        config = ConfigFile(
            default_rules=None,
            rules={},
        )

        assert config.default_rules is None

    def test_empty_config(self):
        """Test empty configuration."""
        config = ConfigFile()

        assert config.default_rules is None
        assert len(config.rules) == 0

    def test_mixed_rule_types(self):
        """Test config with different rule types."""
        config = ConfigFile(
            rules={
                "bash.rule": PreUseBashRuleConfig(
                    type="pre_use_bash",
                    pattern="git.*",
                ),
                "path.rule": PathAccessRuleConfig(
                    type="path_access",
                    pattern="*.env",
                ),
            }
        )

        assert len(config.rules) == 2
        assert isinstance(config.rules["bash.rule"], PreUseBashRuleConfig)
        assert isinstance(config.rules["path.rule"], PathAccessRuleConfig)

    def test_invalid_default_rules_type(self):
        """Test validation of invalid default_rules type."""
        with pytest.raises(ValidationError) as exc_info:
            ConfigFile(default_rules=42)  # Invalid type

        errors = exc_info.value.errors()
        # Pydantic union types produce multiple errors for different attempted types
        assert len(errors) >= 1
        error_messages = " ".join([error["msg"] for error in errors])
        assert "boolean" in error_messages or "list" in error_messages

    def test_invalid_default_rules_list_item(self):
        """Test validation of invalid item in default_rules list."""
        with pytest.raises(ValidationError) as exc_info:
            ConfigFile(default_rules=["valid", 123, "another"])

        errors = exc_info.value.errors()
        # Pydantic union types produce multiple errors for different attempted types
        assert len(errors) >= 1
        error_messages = " ".join([error["msg"] for error in errors])
        assert "string" in error_messages or "boolean" in error_messages

    def test_invalid_rule_id_empty(self):
        """Test validation of empty rule ID."""
        with pytest.raises(ValidationError) as exc_info:
            ConfigFile(rules={"": PreUseBashRuleConfig(type="pre_use_bash", pattern="ls")})

        errors = exc_info.value.errors()
        assert len(errors) == 1
        assert "non-empty string" in errors[0]["msg"]

    def test_invalid_rule_id_whitespace(self):
        """Test validation of whitespace-only rule ID."""
        with pytest.raises(ValidationError) as exc_info:
            ConfigFile(rules={"   ": PreUseBashRuleConfig(type="pre_use_bash", pattern="ls")})

        errors = exc_info.value.errors()
        assert len(errors) == 1
        assert "non-empty string" in errors[0]["msg"]

    def test_discriminated_union_validation(self):
        """Test that discriminated union works correctly."""
        # Valid discriminated union should work
        config_data = {"rules": {"test.rule": {"type": "pre_use_bash", "pattern": "ls"}}}
        config = ConfigFile.model_validate(config_data)
        assert isinstance(config.rules["test.rule"], PreUseBashRuleConfig)

        # Invalid discriminated union should fail
        with pytest.raises(ValidationError) as exc_info:
            ConfigFile.model_validate(
                {"rules": {"test.rule": {"type": "invalid_type", "pattern": "ls"}}}
            )

        errors = exc_info.value.errors()
        assert len(errors) == 1
        assert "Unknown rule type" in str(errors[0])

    def test_from_dict_integration(self):
        """Test creating ConfigFile from dictionary (integration with YAML parsing)."""
        config_dict = {
            "default_rules": True,
            "rules": {
                "security.git": {
                    "type": "path_access",
                    "scope": "write",
                    "action": "deny",
                    "message": "Git access restricted",
                    "priority": 50,
                    "paths": [{"pattern": "**/.git"}, {"pattern": "**/.git/**"}],
                    "enabled": True,
                },
                "performance.grep": {
                    "type": "pre_use_bash",
                    "pattern": "^grep\\b(?!.*\\|)",
                    "action": "warn",
                    "message": "Use ripgrep instead",
                    "priority": 50,
                    "enabled": True,
                },
            },
        }

        config = ConfigFile.model_validate(config_dict)

        assert config.default_rules is True
        assert len(config.rules) == 2

        git_rule = config.rules["security.git"]
        assert isinstance(git_rule, PathAccessRuleConfig)
        assert git_rule.scope == Scope.WRITE
        assert git_rule.action == Action.DENY
        assert len(git_rule.paths) == 2

        grep_rule = config.rules["performance.grep"]
        assert isinstance(grep_rule, PreUseBashRuleConfig)
        assert grep_rule.action == Action.WARN
        assert len(grep_rule.commands) == 1  # Converted from pattern
        assert grep_rule.commands[0].pattern == "^grep\\b(?!.*\\|)"

    def test_invalid_rules_data(self):
        """Test validation of invalid rule data in ConfigFile."""
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

    def test_invalid_rules_section(self):
        """Test validation of invalid rules section in ConfigFile."""
        with pytest.raises(ValidationError):
            ConfigFile.model_validate(
                {
                    "rules": "not a dictionary"  # Invalid rules section
                }
            )
