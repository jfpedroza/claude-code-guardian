"""Unit tests for CLI rules module."""

from ccguardian.cli.rules_command import (
    format_rule,
)
from ccguardian.rules import (
    Action,
    CommandPattern,
    PathAccessRule,
    PathPattern,
    PreUseBashRule,
    Scope,
)


class TestRulesFormatting:
    def test_format_rule_pre_use_bash(self):
        rule = PreUseBashRule(
            id="bash.test",
            commands=[
                CommandPattern(pattern="test.*", action=Action.DENY),
                CommandPattern(pattern="another.*", action=None),  # Should use rule action
            ],
            action=Action.WARN,
            priority=40,
        )

        result = format_rule(rule)

        expected = [
            "ID: bash.test | Type: pre_use_bash | Priority: 40",
            "Commands:",
            "- `test.*` (action: deny)",
            "- `another.*` (action: warn)",  # Falls back to rule action
            "",
        ]
        assert result == expected

    def test_format_rule_path_access(self):
        rule = PathAccessRule(
            id="path.test",
            paths=[
                PathPattern(pattern="**/*.env", scope=Scope.READ, action=Action.DENY),
                PathPattern(
                    pattern="**/*.log", scope=None, action=None
                ),  # Should use rule defaults
            ],
            action=Action.ALLOW,
            priority=60,
        )

        result = format_rule(rule)

        expected = [
            "ID: path.test | Type: path_access | Priority: 60",
            "Paths:",
            "- `**/*.env` [read] (action: deny)",
            "- `**/*.log` [read_write] (action: allow)",  # Falls back to rule scope and action
            "",
        ]
        assert result == expected
