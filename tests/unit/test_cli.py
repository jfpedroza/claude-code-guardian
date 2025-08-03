"""Tests for CLI functionality."""

from unittest.mock import Mock, patch

import pytest
from click.testing import CliRunner

from ccguardian.cli import hook, main


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

    @patch("ccguardian.cli.create_context")
    def test_hook_non_bash_tool_exits_success(
        self, mock_create_context, mock_pretool_context_non_bash
    ):
        """Test that non-Bash tools exit successfully without validation."""
        mock_create_context.return_value = mock_pretool_context_non_bash

        result = self.runner.invoke(hook, [])

        # Should complete without error
        assert result.exit_code == 0
        mock_pretool_context_non_bash.output.exit_success.assert_called_once()

    @patch("ccguardian.cli.create_context")
    def test_hook_empty_command_exits_success(self, mock_create_context, mock_pretool_context):
        """Test that empty commands exit successfully."""
        mock_pretool_context.tool_input = {"command": ""}
        mock_create_context.return_value = mock_pretool_context

        result = self.runner.invoke(hook, [])

        assert result.exit_code == 0
        mock_pretool_context.output.exit_success.assert_called_once()

    @patch("ccguardian.cli.create_context")
    def test_hook_valid_command_exits_success(self, mock_create_context, mock_pretool_context):
        """Test that valid commands exit successfully."""
        mock_pretool_context.tool_input = {"command": "ls -la"}
        mock_create_context.return_value = mock_pretool_context

        result = self.runner.invoke(hook, [])

        assert result.exit_code == 0
        # Should not call deny, command should pass through
        mock_pretool_context.output.deny.assert_not_called()

    @patch("ccguardian.cli.create_context")
    def test_hook_invalid_command_denies(self, mock_create_context, mock_pretool_context):
        """Test that invalid commands are denied with reason."""
        mock_pretool_context.tool_input = {"command": "grep pattern file.txt"}
        mock_create_context.return_value = mock_pretool_context

        result = self.runner.invoke(hook, [])

        assert result.exit_code == 0
        mock_pretool_context.output.deny.assert_called_once()
        call_args = mock_pretool_context.output.deny.call_args[0][0]
        assert "rg" in call_args
        assert "•" in call_args  # bullet point format

    @patch("ccguardian.cli.create_context")
    def test_hook_missing_command_key(self, mock_create_context, mock_pretool_context):
        """Test hook behavior when command key is missing from tool_input."""
        mock_pretool_context.tool_input = {}
        mock_create_context.return_value = mock_pretool_context

        result = self.runner.invoke(hook, [])

        assert result.exit_code == 0
        mock_pretool_context.output.exit_success.assert_called_once()

    @patch("ccguardian.cli.create_context")
    def test_hook_context_assertion_error(self, mock_create_context):
        """Test hook behavior when context is not PreToolUseContext."""
        mock_context = Mock()
        mock_context.__class__.__name__ = "PostToolUseContext"
        mock_create_context.return_value = mock_context

        # This should raise AssertionError due to isinstance check
        with pytest.raises(AssertionError):
            self.runner.invoke(hook, [], catch_exceptions=False)
