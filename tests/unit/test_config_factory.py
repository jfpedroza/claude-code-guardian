"""Tests for rule factory functionality."""

import pytest

from ccguardian.config import ConfigValidationError, RuleFactory
from ccguardian.rules import (
    DEFAULT_PRIORITY,
    Action,
    PathAccessRule,
    PreUseBashRule,
    Scope,
)


class TestRuleFactory:
    def setup_method(self):
        self.factory = RuleFactory()

    def test_create_pre_use_bash_rule_single_pattern(self):
        config = {
            "type": "pre_use_bash",
            "pattern": r"^grep\b(?!.*\|)",
            "action": "deny",
            "message": "Use ripgrep instead",
            "priority": DEFAULT_PRIORITY,
            "enabled": True,
        }

        rule = self.factory.create_rule("test.rule", config)

        assert isinstance(rule, PreUseBashRule)
        assert rule.id == "test.rule"
        assert rule.enabled is True
        assert rule.priority == DEFAULT_PRIORITY
        assert rule.action == Action.DENY
        assert rule.message == "Use ripgrep instead"
        assert len(rule.commands) == 1
        assert rule.commands[0].pattern == r"^grep\b(?!.*\|)"
        assert rule.commands[0].action is None  # Uses rule-level action
        assert rule.commands[0].message is None  # Uses rule-level message

    def test_create_pre_use_bash_rule_commands_list(self):
        config = {
            "type": "pre_use_bash",
            "commands": [
                {
                    "pattern": "git push$",
                    "action": "allow",
                    "message": "Standard git push allowed",
                },
                {
                    "pattern": "git push.*--force",
                    "action": "ask",
                    "message": "Force push requires confirmation",
                },
                {"pattern": "git push origin"},  # No action/message overrides
            ],
            "action": "deny",
            "message": "Git operation blocked",
            "priority": 100,
            "enabled": True,
        }

        rule = self.factory.create_rule("git.operations", config)

        assert isinstance(rule, PreUseBashRule)
        assert rule.id == "git.operations"
        assert rule.priority == 100
        assert rule.action == Action.DENY
        assert rule.message == "Git operation blocked"
        assert len(rule.commands) == 3

        assert rule.commands[0].pattern == "git push$"
        assert rule.commands[0].action == Action.ALLOW
        assert rule.commands[0].message == "Standard git push allowed"

        assert rule.commands[1].pattern == "git push.*--force"
        assert rule.commands[1].action == Action.ASK
        assert rule.commands[1].message == "Force push requires confirmation"

        assert rule.commands[2].pattern == "git push origin"
        assert rule.commands[2].action is None  # Will use rule-level action
        assert rule.commands[2].message is None  # Will use rule-level message

    def test_create_path_access_rule_single_pattern(self):
        config = {
            "type": "path_access",
            "pattern": "**/.env*",
            "scope": "read_write",
            "action": "deny",
            "message": "Access to environment files blocked",
            "priority": 80,
            "enabled": True,
        }

        rule = self.factory.create_rule("security.env_files", config)

        assert isinstance(rule, PathAccessRule)
        assert rule.id == "security.env_files"
        assert rule.enabled is True
        assert rule.priority == 80
        assert rule.action == Action.DENY
        assert rule.message == "Access to environment files blocked"
        assert rule.scope == Scope.READ_WRITE
        assert len(rule.paths) == 1
        assert rule.paths[0].pattern == "**/.env*"
        assert rule.paths[0].scope is None  # Uses rule-level scope
        assert rule.paths[0].action is None  # Uses rule-level action
        assert rule.paths[0].message is None  # Uses rule-level message

    def test_create_path_access_rule_paths_list(self):
        config = {
            "type": "path_access",
            "paths": [
                {
                    "pattern": "**/.git/**",
                    "scope": "write",
                    "action": "warn",
                    "message": "Direct .git manipulation detected",
                },
                {
                    "pattern": "**/config/secrets/**",
                    "scope": "read",
                    "action": "deny",
                    "message": "Access to secrets directory blocked",
                },
                {"pattern": "**/*.log"},  # No overrides
            ],
            "action": "allow",
            "scope": "read_write",
            "priority": 70,
            "enabled": True,
        }

        rule = self.factory.create_rule("security.sensitive_files", config)

        assert isinstance(rule, PathAccessRule)
        assert rule.id == "security.sensitive_files"
        assert rule.priority == 70
        assert rule.action == Action.ALLOW
        assert rule.scope == Scope.READ_WRITE
        assert len(rule.paths) == 3

        assert rule.paths[0].pattern == "**/.git/**"
        assert rule.paths[0].scope == Scope.WRITE
        assert rule.paths[0].action == Action.WARN
        assert rule.paths[0].message == "Direct .git manipulation detected"

        assert rule.paths[1].pattern == "**/config/secrets/**"
        assert rule.paths[1].scope == Scope.READ
        assert rule.paths[1].action == Action.DENY
        assert rule.paths[1].message == "Access to secrets directory blocked"

        assert rule.paths[2].pattern == "**/*.log"
        assert rule.paths[2].scope is None  # Will use rule-level scope
        assert rule.paths[2].action is None  # Will use rule-level action
        assert rule.paths[2].message is None  # Will use rule-level message

    def test_create_rule_with_defaults(self):
        config = {"type": "pre_use_bash", "pattern": "test"}

        rule = self.factory.create_rule("minimal.rule", config)

        assert isinstance(rule, PreUseBashRule)
        assert rule.id == "minimal.rule"
        assert rule.enabled is True  # Default
        assert rule.priority == DEFAULT_PRIORITY  # Default
        assert rule.action == Action.CONTINUE  # Default for PreUseBashRule
        assert rule.message is None  # Default
        assert len(rule.commands) == 1

    def test_create_rule_missing_type(self):
        config = {"pattern": "test"}

        with pytest.raises(ConfigValidationError, match="missing required 'type' field"):
            self.factory.create_rule("invalid.rule", config)

    def test_create_rule_unknown_type(self):
        config = {"type": "unknown_type", "pattern": "test"}

        with pytest.raises(ConfigValidationError, match="Unknown rule type 'unknown_type'"):
            self.factory.create_rule("invalid.rule", config)

    def test_create_rule_no_patterns(self):
        config = {"type": "pre_use_bash", "action": "deny"}

        with pytest.raises(
            ConfigValidationError,
            match="PreUseBashRule requires either 'pattern' or 'commands' field",
        ):
            self.factory.create_rule("invalid.rule", config)

    @pytest.mark.parametrize(
        ("input_value", "expected"),
        [
            ("allow", Action.ALLOW),
            ("DENY", Action.DENY),  # Case insensitive
            ("ask", Action.ASK),
            (Action.WARN, Action.WARN),  # Already enum
        ],
    )
    def test_parse_action_valid(self, input_value, expected):
        assert self.factory._parse_action(input_value, "test.rule") == expected

    def test_parse_action_invalid_string(self):
        with pytest.raises(ConfigValidationError, match="Invalid action value"):
            self.factory._parse_action("invalid", "test.rule")

    def test_parse_action_invalid_type(self):
        with pytest.raises(ConfigValidationError, match="Action must be a string"):
            self.factory._parse_action(123, "test.rule")

    def test_parse_action_none(self):
        assert self.factory._parse_action(None, "test.rule") is None

    @pytest.mark.parametrize(
        ("input_value", "expected"),
        [
            ("read", Scope.READ),
            ("WRITE", Scope.WRITE),  # Case insensitive
            ("read_write", Scope.READ_WRITE),
            (Scope.READ, Scope.READ),  # Already enum
        ],
    )
    def test_parse_scope_valid(self, input_value, expected):
        assert self.factory._parse_scope(input_value, "test.rule") == expected

    def test_parse_scope_invalid_string(self):
        with pytest.raises(ConfigValidationError, match="Invalid scope value"):
            self.factory._parse_scope("invalid", "test.rule")

    def test_parse_scope_invalid_type(self):
        with pytest.raises(ConfigValidationError, match="Scope must be a string"):
            self.factory._parse_scope(123, "test.rule")

    def test_parse_scope_none(self):
        assert self.factory._parse_scope(None, "test.rule") is None

    def test_convert_command_patterns_invalid_commands(self):
        config = {"commands": "not a list"}
        with pytest.raises(ConfigValidationError, match="'commands' field must be a list"):
            self.factory._convert_to_command_patterns(config, "test.rule")

        config = {"commands": [{"no_pattern": "value"}]}
        with pytest.raises(
            ConfigValidationError, match="Command pattern at index 0 missing 'pattern' field"
        ):
            self.factory._convert_to_command_patterns(config, "test.rule")

        config = {"commands": ["not a dict"]}
        with pytest.raises(
            ConfigValidationError, match="Command configuration at index 0 must be a dictionary"
        ):
            self.factory._convert_to_command_patterns(config, "test.rule")

    def test_convert_path_patterns_invalid_paths(self):
        config = {"paths": "not a list"}
        with pytest.raises(ConfigValidationError, match="'paths' field must be a list"):
            self.factory._convert_to_path_patterns(config, "test.rule")

        config = {"paths": [{"no_pattern": "value"}]}
        with pytest.raises(
            ConfigValidationError, match="Path pattern at index 0 missing 'pattern' field"
        ):
            self.factory._convert_to_path_patterns(config, "test.rule")

        config = {"paths": ["not a dict"]}
        with pytest.raises(
            ConfigValidationError, match="Path configuration at index 0 must be a dictionary"
        ):
            self.factory._convert_to_path_patterns(config, "test.rule")

    def test_create_rules_from_merged_data(self):
        merged_data = {
            "security.dangerous": {
                "type": "pre_use_bash",
                "pattern": "rm -rf",
                "action": "deny",
                "priority": 100,
            },
            "performance.grep": {
                "type": "pre_use_bash",
                "pattern": "grep",
                "action": "deny",
                "priority": DEFAULT_PRIORITY,
            },
            "security.env_files": {
                "type": "path_access",
                "pattern": "**/.env*",
                "action": "deny",
                "priority": 80,
            },
        }

        rules = self.factory.create_rules_from_merged_data(merged_data)

        assert len(rules) == 3

        assert rules[0].id == "security.dangerous"  # Priority 100
        assert rules[0].priority == 100
        assert rules[1].id == "security.env_files"  # Priority 80
        assert rules[1].priority == 80
        assert rules[2].id == "performance.grep"  # Priority 50
        assert rules[2].priority == DEFAULT_PRIORITY

        assert isinstance(rules[0], PreUseBashRule)
        assert isinstance(rules[1], PathAccessRule)
        assert isinstance(rules[2], PreUseBashRule)

    def test_create_rules_from_merged_data_with_invalid_rule(self):
        merged_data = {
            "valid.rule": {
                "type": "pre_use_bash",
                "pattern": "test",
                "action": "deny",
            },
            "invalid.rule": {
                "type": "unknown_type",  # This will cause an error
                "pattern": "test",
            },
        }

        with pytest.raises(ConfigValidationError, match="Unknown rule type 'unknown_type'"):
            self.factory.create_rules_from_merged_data(merged_data)

    def test_create_rules_from_empty_data(self):
        rules = self.factory.create_rules_from_merged_data({})
        assert rules == []

    def test_rule_priority_sorting(self):
        merged_data = {
            "rule.c": {"type": "pre_use_bash", "pattern": "c", "priority": DEFAULT_PRIORITY},
            "rule.a": {"type": "pre_use_bash", "pattern": "a", "priority": 100},
            "rule.b": {"type": "pre_use_bash", "pattern": "b", "priority": DEFAULT_PRIORITY},
            "rule.d": {"type": "pre_use_bash", "pattern": "d", "priority": 100},
        }

        rules = self.factory.create_rules_from_merged_data(merged_data)

        expected_order = ["rule.a", "rule.d", "rule.b", "rule.c"]
        actual_order = [rule.id for rule in rules]

        assert actual_order == expected_order

    def test_create_rule_exception_handling(self):
        config = {"type": "pre_use_bash", "priority": "not an integer"}

        with pytest.raises(
            ConfigValidationError,
            match="PreUseBashRule requires either 'pattern' or 'commands' field",
        ):
            self.factory.create_rule("error.rule", config)

    def test_create_rule_pattern_commands_mutually_exclusive(self):
        config = {
            "type": "pre_use_bash",
            "pattern": "test",
            "commands": [{"pattern": "another", "action": "deny"}],
        }

        with pytest.raises(
            ConfigValidationError,
            match="Cannot specify both 'pattern' and 'commands' fields - they are mutually exclusive",
        ):
            self.factory.create_rule("conflicting.rule", config)

    def test_create_rule_pattern_paths_mutually_exclusive(self):
        config = {
            "type": "path_access",
            "pattern": "*.env",
            "paths": [{"pattern": "*.log", "action": "deny"}],
        }

        with pytest.raises(
            ConfigValidationError,
            match="Cannot specify both 'pattern' and 'paths' fields - they are mutually exclusive",
        ):
            self.factory.create_rule("conflicting.rule", config)

    def test_validate_regex_pattern_valid(self):
        valid_patterns = [
            r"^grep\b(?!.*\|)",
            r"rm -rf",
            r"sudo.*rm",
            r"git push.*--force",
            r"\d+",
            r"[a-zA-Z_]\w*",
            r"(?i)case.*insensitive",
            r"^start.*end$",
        ]

        for pattern in valid_patterns:
            assert self.factory._validate_regex_pattern(pattern), (
                f"Pattern should be valid: {pattern}"
            )

    def test_validate_regex_pattern_invalid(self):
        invalid_patterns = [
            r"[unclosed",
            r"(?P<invalid",
            r"(?P<>invalid)",
            r"(?<invalid)",
            r"*invalid",
            r"(?P<123>invalid)",
            r"(?P<test",
        ]

        for pattern in invalid_patterns:
            assert not self.factory._validate_regex_pattern(pattern), (
                f"Pattern should be invalid: {pattern}"
            )

    def test_validate_glob_pattern_valid(self):
        valid_patterns = [
            "*.env",
            "**/.env*",
            "**/config/**",
            "*.{txt,log}",
            "file[0-9].txt",
            "**/*.py",
            "src/**/*.js",
            "/absolute/path/*",
            "relative/path/*.conf",
        ]

        for pattern in valid_patterns:
            assert self.factory._validate_glob_pattern(pattern), (
                f"Pattern should be valid: {pattern}"
            )

    def test_validate_glob_pattern_invalid(self):
        # Test empty pattern - should be invalid with improved validation
        assert not self.factory._validate_glob_pattern(""), "Empty pattern should be invalid"

        # Test None handling
        result = self.factory._validate_glob_pattern(None)
        assert not result, "None pattern should be invalid"

        # Test unbalanced brackets - should be invalid with improved validation
        assert not self.factory._validate_glob_pattern("[unclosed"), (
            "Unbalanced bracket should be invalid"
        )
        assert not self.factory._validate_glob_pattern("unopened]"), (
            "Unmatched closing bracket should be invalid"
        )
        assert not self.factory._validate_glob_pattern("[[nested]]"), (
            "Nested brackets should be invalid"
        )

    def test_create_pre_use_bash_rule_invalid_regex(self):
        config = {
            "type": "pre_use_bash",
            "pattern": "[unclosed",  # Invalid regex
            "action": "deny",
        }

        with pytest.raises(ConfigValidationError, match="Invalid regex pattern: '\\[unclosed'"):
            self.factory.create_rule("invalid.regex", config)

    def test_create_pre_use_bash_rule_invalid_regex_in_commands(self):
        config = {
            "type": "pre_use_bash",
            "commands": [
                {"pattern": "valid.*pattern", "action": "allow"},
                {"pattern": "[unclosed", "action": "deny"},
                {"pattern": "another.*valid", "action": "warn"},
            ],
            "action": "continue",
        }

        with pytest.raises(
            ConfigValidationError, match="Invalid regex pattern at index 1: '\\[unclosed'"
        ):
            self.factory.create_rule("mixed.regex", config)

    def test_create_path_access_rule_invalid_glob_in_paths(self):
        """Test creating PathAccessRule with mixed valid/invalid globs in paths list."""
        config = {
            "type": "path_access",
            "paths": [
                {"pattern": "**/*.env", "action": "deny"},
                {"action": "warn"},
                {"pattern": "**/*.log", "action": "allow"},
            ],
            "action": "deny",
        }

        with pytest.raises(
            ConfigValidationError, match="Path pattern at index 1 missing 'pattern' field"
        ):
            self.factory.create_rule("mixed.globs", config)
