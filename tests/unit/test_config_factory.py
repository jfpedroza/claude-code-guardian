"""Tests for rule factory functionality."""

from ccguardian.config import PathAccessRuleConfig, PreUseBashRuleConfig, RuleFactory
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

    def test_create_pre_use_bash_rule(self):
        config = PreUseBashRuleConfig.model_validate(
            {
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
        )

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

    def test_create_path_access_rule(self):
        config = PathAccessRuleConfig.model_validate(
            {
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
        )

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
        config = PreUseBashRuleConfig.model_validate(
            {"type": "pre_use_bash", "commands": [{"pattern": "test"}]}
        )

        rule = self.factory.create_rule("minimal.rule", config)

        assert isinstance(rule, PreUseBashRule)
        assert rule.id == "minimal.rule"
        assert rule.enabled is True  # Default
        assert rule.priority == DEFAULT_PRIORITY  # Default
        assert rule.action == Action.CONTINUE  # Default for PreUseBashRule
        assert rule.message is None  # Default
        assert len(rule.commands) == 1

    def test_create_rules_from_merged_data(self):
        merged_data = {
            "security.dangerous": PreUseBashRuleConfig.model_validate(
                {
                    "type": "pre_use_bash",
                    "commands": [{"pattern": "rm -rf"}],
                    "action": "deny",
                    "priority": 100,
                }
            ),
            "performance.grep": PreUseBashRuleConfig.model_validate(
                {
                    "type": "pre_use_bash",
                    "commands": [{"pattern": "grep"}],
                    "action": "deny",
                    "priority": DEFAULT_PRIORITY,
                }
            ),
            "security.env_files": PathAccessRuleConfig.model_validate(
                {
                    "type": "path_access",
                    "paths": [{"pattern": "**/.env*"}],
                    "action": "deny",
                    "priority": 80,
                }
            ),
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

    def test_rule_priority_sorting(self):
        merged_data = {
            "rule.c": PreUseBashRuleConfig.model_validate(
                {
                    "type": "pre_use_bash",
                    "commands": [{"pattern": "c"}],
                    "priority": DEFAULT_PRIORITY,
                }
            ),
            "rule.a": PathAccessRuleConfig.model_validate(
                {"type": "path_access", "pattern": "a", "priority": 100}
            ),
            "rule.b": PreUseBashRuleConfig.model_validate(
                {
                    "type": "pre_use_bash",
                    "commands": [{"pattern": "b"}],
                    "priority": DEFAULT_PRIORITY,
                }
            ),
            "rule.d": PathAccessRuleConfig.model_validate(
                {"type": "path_access", "pattern": "d", "priority": 100}
            ),
        }

        rules = self.factory.create_rules_from_merged_data(merged_data)

        expected_order = ["rule.a", "rule.d", "rule.b", "rule.c"]
        actual_order = [rule.id for rule in rules]

        assert actual_order == expected_order
