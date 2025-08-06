"""Tests for CLI functionality."""

from unittest.mock import Mock, patch

from click.testing import CliRunner

from ccguardian.cli import main
from ccguardian.cli.main import hook
from ccguardian.cli.rules_command import rules


class TestCLI:
    """Test CLI command functionality."""

    def setup_method(self):
        """Set up test environment."""
        self.runner = CliRunner()

    def test_main_no_args_shows_help_and_exits_1(self):
        """Test that running CLI with no args shows help and exits with code 1."""
        result = self.runner.invoke(main, [])

        assert result.exit_code == 1
        assert "Claude Code Guardian" in result.output
        assert "Usage:" in result.output
        assert "Commands:" in result.output
        assert "hook" in result.output

    def test_main_help_flag(self):
        """Test that -h and --help flags work."""
        result_h = self.runner.invoke(main, ["-h"])
        result_help = self.runner.invoke(main, ["--help"])

        assert result_h.exit_code == 0
        assert result_help.exit_code == 0
        assert result_h.output == result_help.output
        assert "Claude Code Guardian" in result_h.output


class TestHookCommand:
    """Test hook CLI command."""

    def setup_method(self):
        """Set up test environment."""
        self.runner = CliRunner()

    def test_hook_help(self):
        """Test hook command help."""
        result = self.runner.invoke(main, ["hook", "--help"])

        assert result.exit_code == 0
        assert "Claude Code hook entry point" in result.output

    @patch("ccguardian.cli.main.create_context")
    def test_hook_non_bash_tool_exits_success(
        self, mock_create_context, mock_pretool_context_non_bash
    ):
        """Test that non-Bash tools exit successfully without validation."""
        mock_create_context.return_value = mock_pretool_context_non_bash

        result = self.runner.invoke(hook, [])

        # Should complete without error
        assert result.exit_code == 0
        mock_pretool_context_non_bash.output.exit_success.assert_called_once()

    @patch("ccguardian.cli.main.create_context")
    def test_hook_valid_command_exits_success(self, mock_create_context, mock_pretool_context):
        """Test that valid commands exit successfully."""
        mock_pretool_context.tool_input = {"command": "ls -la"}
        mock_create_context.return_value = mock_pretool_context

        result = self.runner.invoke(hook, [])

        assert result.exit_code == 0
        # Should not call deny, command should pass through
        mock_pretool_context.output.deny.assert_not_called()

    @patch("ccguardian.cli.main.create_context")
    def test_hook_invalid_grep_command_denies(self, mock_create_context, mock_pretool_context):
        """Test that grep commands are denied with reason."""
        mock_pretool_context.tool_input = {"command": "grep pattern file.txt"}
        mock_create_context.return_value = mock_pretool_context

        result = self.runner.invoke(hook, [])

        assert result.exit_code == 0
        mock_pretool_context.output.deny.assert_called_once()
        call_args = mock_pretool_context.output.deny.call_args[0][0]
        assert "rg" in call_args
        assert "ripgrep" in call_args  # Check for expected content

    @patch("ccguardian.cli.main.create_context")
    def test_hook_invalid_find_command_denies(self, mock_create_context, mock_pretool_context):
        """Test that find commands are denied with reason."""
        mock_pretool_context.tool_input = {"command": "find /path -name '*.txt'"}
        mock_create_context.return_value = mock_pretool_context

        result = self.runner.invoke(hook, [])

        assert result.exit_code == 0
        mock_pretool_context.output.deny.assert_called_once()
        call_args = mock_pretool_context.output.deny.call_args[0][0]
        assert "rg --files" in call_args
        assert "performance" in call_args

    @patch("ccguardian.cli.main.create_context")
    def test_hook_non_pretooluse_context_does_nothing(self, mock_create_context):
        """Test hook behavior when context is not PreToolUseContext."""
        mock_context = Mock()
        mock_context.__class__.__name__ = "PostToolUseContext"
        mock_create_context.return_value = mock_context

        result = self.runner.invoke(hook, [])

        # Should exit successfully and do nothing (no method calls on context)
        assert result.exit_code == 0


class TestRulesCommand:
    def setup_method(self):
        self.runner = CliRunner()

    def test_rules_help(self):
        result = self.runner.invoke(main, ["rules", "--help"])

        assert result.exit_code == 0
        assert "Display configuration diagnostics and rule information" in result.output

    def test_rules_command_integration(self):
        result = self.runner.invoke(rules, [])

        assert result.exit_code == 0

        assert "Configuration Sources:" in result.output
        assert "✓ Default:" in result.output
        assert "✗ User:" in result.output
        assert "✗ Shared:" in result.output
        assert "✗ Local:" in result.output
        assert "✗ Environment: CLAUDE_CODE_GUARDIAN_CONFIG (not set)" in result.output

        assert "Merged Configuration:" in result.output
        assert "Default Rules: enabled" in result.output
        assert "Total Rules:" in result.output
        assert "Active Rules:" in result.output

        assert "Rule Evaluation Order (by priority):" in result.output
        assert "performance.grep_suggestion" in result.output
        assert "performance.find_suggestion" in result.output
        assert "Type: pre_use_bash" in result.output
        assert "Priority: 50" in result.output

        assert "Commands:" in result.output
        assert "action: deny" in result.output

    def test_rules_command_with_env_var(self):
        import os
        from unittest.mock import patch

        with patch.dict(os.environ, {"CLAUDE_CODE_GUARDIAN_CONFIG": "/tmp/custom"}):
            result = self.runner.invoke(rules, [])

        assert result.exit_code == 0
        assert "✓ Environment: CLAUDE_CODE_GUARDIAN_CONFIG=/tmp/custom" in result.output
