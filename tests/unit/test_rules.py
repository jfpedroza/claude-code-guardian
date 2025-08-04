"""Tests for rule evaluation functionality."""

from unittest.mock import Mock

from cchooks import PostToolUseContext

from ccguardian.rules import (
    Action,
    CommandPattern,
    PathAccessRule,
    PathPattern,
    PreUseBashRule,
    Scope,
)
from tests.utils import (
    pre_use_bash_context,
    pre_use_context,
    pre_use_read_context,
    pre_use_write_context,
)


class TestPreUseBashRule:
    def test_evaluate_rule_disabled_returns_none(self):
        """Test that disabled rules return None."""
        rule = PreUseBashRule(
            id="test-rule",
            enabled=False,
            commands=[CommandPattern(pattern="grep")],
        )
        context = pre_use_bash_context("grep test")

        result = rule.evaluate(context)
        assert result is None

    def test_evaluate_non_pretooluse_context_returns_none(self):
        """Test that non-PreToolUseContext returns None."""
        rule = PreUseBashRule(
            id="test-rule",
            commands=[CommandPattern(pattern="grep")],
        )
        context = Mock(spec=PostToolUseContext)

        result = rule.evaluate(context)
        assert result is None

    def test_evaluate_non_bash_tool_returns_none(self):
        """Test that non-Bash tools return None."""
        rule = PreUseBashRule(
            id="test-rule",
            commands=[CommandPattern(pattern="grep")],
        )
        context = pre_use_read_context("/some/file.txt")

        result = rule.evaluate(context)
        assert result is None

    def test_evaluate_missing_command_returns_none(self):
        """Test that missing command returns None."""
        rule = PreUseBashRule(
            id="test-rule",
            commands=[CommandPattern(pattern="grep")],
        )
        context = pre_use_context("Bash", other="value")

        result = rule.evaluate(context)
        assert result is None

    def test_evaluate_empty_command_returns_none(self):
        """Test that empty command returns None."""
        rule = PreUseBashRule(
            id="test-rule",
            commands=[CommandPattern(pattern="grep")],
        )
        context = pre_use_bash_context("")

        result = rule.evaluate(context)

        assert result is None

    def test_evaluate_pattern_match_with_rule_defaults(self):
        """Test pattern match using rule default action and message."""
        rule = PreUseBashRule(
            id="test-rule",
            action=Action.SUGGEST,
            message="Use rg instead",
            commands=[CommandPattern(pattern=r"^grep\b")],
        )
        context = pre_use_bash_context("grep test file.txt")

        result = rule.evaluate(context)

        assert result is not None
        assert result.rule_id == "test-rule"
        assert result.action == Action.SUGGEST
        assert result.message == "Use rg instead"
        assert result.matched_pattern == r"^grep\b"

    def test_evaluate_pattern_match_with_pattern_overrides(self):
        """Test pattern match with pattern-specific action and message."""
        rule = PreUseBashRule(
            id="test-rule",
            action=Action.SUGGEST,
            message="Default message",
            commands=[
                CommandPattern(
                    pattern=r"^grep\b", action=Action.DENY, message="Custom grep message"
                )
            ],
        )
        context = pre_use_bash_context("grep test file.txt")

        result = rule.evaluate(context)

        assert result is not None
        assert result.rule_id == "test-rule"
        assert result.action == Action.DENY
        assert result.message == "Custom grep message"
        assert result.matched_pattern == r"^grep\b"

    def test_evaluate_pattern_match_with_fallback_message(self):
        """Test pattern match with no rule or pattern message."""
        rule = PreUseBashRule(
            id="test-rule",
            action=Action.SUGGEST,
            # No rule message
            commands=[
                CommandPattern(pattern=r"^grep\b")
                # No pattern message
            ],
        )
        context = pre_use_bash_context("grep test file.txt")

        result = rule.evaluate(context)

        assert result is not None
        assert result.rule_id == "test-rule"
        assert result.action == Action.SUGGEST
        assert result.message == r"Command matched pattern: ^grep\b"
        assert result.matched_pattern == r"^grep\b"

    def test_evaluate_multiple_patterns_first_match_wins(self):
        """Test that first matching pattern wins."""
        rule = PreUseBashRule(
            id="test-rule",
            commands=[
                CommandPattern(pattern=r"^grep", action=Action.SUGGEST, message="First pattern"),
                CommandPattern(
                    pattern=r"grep.*test", action=Action.DENY, message="Second pattern"
                ),
            ],
        )
        context = pre_use_bash_context("grep test file.txt")

        result = rule.evaluate(context)

        assert result is not None
        assert result.action == Action.SUGGEST
        assert result.message == "First pattern"
        assert result.matched_pattern == r"^grep"

    def test_evaluate_no_pattern_matches_returns_none(self):
        """Test that no pattern matches returns None."""
        rule = PreUseBashRule(
            id="test-rule",
            commands=[
                CommandPattern(pattern=r"^grep\b"),
                CommandPattern(pattern=r"^find\b"),
            ],
        )
        context = pre_use_bash_context("ls -la")

        result = rule.evaluate(context)
        assert result is None

    def test_evaluate_pattern_matching_case_sensitive(self):
        """Test that pattern matching is case sensitive by default."""
        rule = PreUseBashRule(
            id="test-rule",
            commands=[CommandPattern(pattern=r"^grep\b")],
        )
        context = pre_use_bash_context("GREP test file.txt")

        result = rule.evaluate(context)
        assert result is None

    def test_evaluate_regex_patterns_work_correctly(self):
        """Test that regex patterns work correctly."""
        rule = PreUseBashRule(
            id="test-rule",
            commands=[
                CommandPattern(pattern=r"rm\s+-rf"),
                CommandPattern(pattern=r"sudo\s+rm"),
            ],
        )
        context = pre_use_bash_context("rm -rf /tmp/test")

        result = rule.evaluate(context)

        assert result is not None
        assert result.matched_pattern == r"rm\s+-rf"


class TestPathAccessRule:
    def test_evaluate_rule_disabled_returns_none(self):
        """Test that disabled rules return None."""
        rule = PathAccessRule(
            id="test-rule",
            enabled=False,
            paths=[PathPattern(pattern="*.env")],
        )
        context = pre_use_read_context("/test/.env")

        result = rule.evaluate(context)
        assert result is None

    def test_evaluate_non_pretooluse_context_returns_none(self):
        """Test that non-PreToolUseContext returns None."""
        rule = PathAccessRule(
            id="test-rule",
            paths=[PathPattern(pattern="*.env")],
        )
        context = Mock(spec=PostToolUseContext)

        result = rule.evaluate(context)
        assert result is None

    def test_evaluate_non_file_access_tool_returns_none(self):
        """Test that non-file access tools return None."""
        rule = PathAccessRule(
            id="test-rule",
            paths=[PathPattern(pattern="*.env")],
        )
        context = pre_use_context("Bash")

        result = rule.evaluate(context)
        assert result is None

    def test_evaluate_missing_file_path_returns_none(self):
        """Test that missing file_path returns None."""
        rule = PathAccessRule(
            id="test-rule",
            paths=[PathPattern(pattern="*.env")],
        )
        context = pre_use_context("Read", other="value")

        result = rule.evaluate(context)
        assert result is None

    def test_evaluate_empty_file_path_returns_none(self):
        """Test that empty file_path returns None."""
        rule = PathAccessRule(
            id="test-rule",
            paths=[PathPattern(pattern="*.env")],
        )
        context = pre_use_read_context("")

        result = rule.evaluate(context)
        assert result is None

    def test_evaluate_read_tool_matches_pattern(self):
        """Test Read tool matches path pattern."""
        rule = PathAccessRule(
            id="test-rule",
            action=Action.DENY,
            message="Environment files blocked",
            paths=[PathPattern(pattern="*.env")],
        )
        context = pre_use_read_context("/home/user/.env")

        result = rule.evaluate(context)

        assert result is not None
        assert result.rule_id == "test-rule"
        assert result.action == Action.DENY
        assert result.message == "Environment files blocked"
        assert result.matched_pattern == "*.env"

    def test_evaluate_write_tools_match_pattern(self):
        """Test that Edit, MultiEdit, Write tools match patterns."""
        for tool_name in ["Edit", "MultiEdit", "Write"]:
            rule = PathAccessRule(
                id="test-rule",
                paths=[PathPattern(pattern="*.env")],
            )
            context = pre_use_write_context("/home/user/.env", tool_name)

            result = rule.evaluate(context)

            assert result is not None
            assert result.matched_pattern == "*.env"

    def test_evaluate_pattern_with_scope_read_only(self):
        """Test pattern with read-only scope blocks Read but not Write."""
        rule = PathAccessRule(
            id="test-rule",
            paths=[PathPattern(pattern="*.log", scope=Scope.READ)],
        )

        # Should match Read operations
        read_context = pre_use_read_context("/var/log/test.log")

        result = rule.evaluate(read_context)
        assert result is not None

        # Should not match Write operations
        write_context = pre_use_write_context("/var/log/test.log")

        result = rule.evaluate(write_context)
        assert result is None

    def test_evaluate_pattern_with_scope_write_only(self):
        """Test pattern with write-only scope blocks Write but not Read."""
        rule = PathAccessRule(
            id="test-rule",
            paths=[PathPattern(pattern="*.cfg", scope=Scope.WRITE)],
        )

        # Should not match Read operations
        read_context = pre_use_read_context("/etc/test.cfg")

        result = rule.evaluate(read_context)
        assert result is None

        # Should match Write operations
        write_context = pre_use_write_context("/etc/test.cfg", "Edit")

        result = rule.evaluate(write_context)
        assert result is not None

    def test_evaluate_pattern_with_scope_read_write(self):
        """Test pattern with read_write scope blocks both operations."""
        rule = PathAccessRule(
            id="test-rule",
            paths=[PathPattern(pattern="*.secret", scope=Scope.READ_WRITE)],
        )

        # Should match Read operations
        read_context = pre_use_read_context("/home/user/api.secret")

        result = rule.evaluate(read_context)
        assert result is not None

        # Should match Write operations
        write_context = pre_use_write_context("/home/user/api.secret")

        result = rule.evaluate(write_context)
        assert result is not None

    def test_evaluate_pattern_overrides_rule_defaults(self):
        """Test pattern-specific action and message override rule defaults."""
        rule = PathAccessRule(
            id="test-rule",
            action=Action.WARN,
            message="Default message",
            paths=[
                PathPattern(pattern="*.env", action=Action.DENY, message="Custom env message")
            ],
        )
        context = pre_use_read_context("/home/user/.env")

        result = rule.evaluate(context)

        assert result is not None
        assert result.action == Action.DENY
        assert result.message == "Custom env message"

    def test_evaluate_fallback_message_generation(self):
        """Test fallback message when no rule or pattern message."""
        rule = PathAccessRule(
            id="test-rule",
            # No rule message
            paths=[
                PathPattern(pattern="*.env")
                # No pattern message
            ],
        )
        context = pre_use_read_context("/home/user/.env")

        result = rule.evaluate(context)

        assert result is not None
        assert result.message == "Path matched pattern: *.env"

    def test_evaluate_glob_patterns_work_correctly(self):
        """Test various glob pattern matching."""
        patterns_and_paths = [
            ("*.env", "/home/user/.env", True),
            ("*.env", "/home/user/config.yaml", False),
            ("**/.env*", "/home/user/.env", True),
            ("**/.env*", "/home/user/.env.local", True),
            ("**/.env*", "/deep/nested/path/.env.prod", True),
            ("**/.git/**", "/home/user/project/.git/config", True),
            ("**/.git/**", "/home/user/project/src/main.py", False),
            ("/etc/**", "/etc/passwd", True),
            ("/etc/**", "/home/user/file", False),
        ]

        for pattern, file_path, should_match in patterns_and_paths:
            rule = PathAccessRule(
                id="test-rule",
                paths=[PathPattern(pattern=pattern)],
            )
            context = pre_use_read_context(file_path)

            result = rule.evaluate(context)

            if should_match:
                assert result is not None, f"Pattern '{pattern}' should match '{file_path}'"
                assert result.matched_pattern == pattern
            else:
                assert result is None, f"Pattern '{pattern}' should not match '{file_path}'"

    def test_evaluate_multiple_patterns_first_match_wins(self):
        """Test that first matching pattern wins."""
        rule = PathAccessRule(
            id="test-rule",
            paths=[
                PathPattern(pattern="*.env", action=Action.WARN, message="First pattern"),
                PathPattern(pattern="**/.env*", action=Action.DENY, message="Second pattern"),
            ],
        )
        context = pre_use_read_context("/home/user/.env")

        result = rule.evaluate(context)

        assert result is not None
        assert result.action == Action.WARN
        assert result.message == "First pattern"
        assert result.matched_pattern == "*.env"

    def test_evaluate_no_pattern_matches_returns_none(self):
        """Test that no pattern matches returns None."""
        rule = PathAccessRule(
            id="test-rule",
            paths=[
                PathPattern(pattern="*.env"),
                PathPattern(pattern="*.secret"),
            ],
        )
        context = pre_use_read_context("/home/user/config.yaml")

        result = rule.evaluate(context)
        assert result is None
