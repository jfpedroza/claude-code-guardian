"""Tests for CLI functionality."""

from unittest.mock import Mock, patch

import pytest
from click.testing import CliRunner

from ccguardian.cli import main
from ccguardian.cli.hook_command import hook
from ccguardian.cli.rules_command import rules
from ccguardian.rules import Action, CommandPattern, PreUseBashRule
from tests.utils import post_use_write_context, pre_use_bash_context


class TestCLI:
    def setup_method(self):
        self.runner = CliRunner()

    def test_main_no_args_shows_help_and_exits_1(self):
        result = self.runner.invoke(main, [])

        assert result.exit_code == 1
        assert "Claude Code Guardian" in result.output
        assert "Usage:" in result.output
        assert "Commands:" in result.output
        assert "hook" in result.output

    @pytest.mark.parametrize("help_flag", ["-h", "--help"])
    def test_main_help_flag(self, help_flag):
        result = self.runner.invoke(main, [help_flag])

        assert result.exit_code == 0
        assert "Claude Code Guardian" in result.output


class TestHookCommand:
    def setup_method(self):
        self.runner = CliRunner()

    def test_hook_help(self):
        result = self.runner.invoke(main, ["hook", "--help"])

        assert result.exit_code == 0
        assert "Claude Code hook entry point" in result.output

    @patch("ccguardian.cli.hook_command.ConfigurationManager")
    @patch("ccguardian.cli.hook_command.safe_create_context")
    def test_hook_non_bash_tool_exits_success(
        self, mock_safe_create_context, mock_config_manager, mock_pretool_context_non_bash
    ):
        mock_safe_create_context.return_value = mock_pretool_context_non_bash

        mock_config = Mock()
        mock_config.active_rules = []
        mock_config_manager.return_value.load_configuration.return_value = mock_config

        result = self.runner.invoke(hook, [])

        assert result.exit_code == 0
        mock_pretool_context_non_bash.output.exit_success.assert_called_once()

    @patch("ccguardian.cli.hook_command.ConfigurationManager")
    @patch("ccguardian.cli.hook_command.safe_create_context")
    def test_hook_no_matching_rules_exits_success(
        self, mock_safe_create_context, mock_config_manager
    ):
        context = pre_use_bash_context("ls -la")
        mock_safe_create_context.return_value = context

        mock_config = Mock()
        mock_config.active_rules = []
        mock_config_manager.return_value.load_configuration.return_value = mock_config

        result = self.runner.invoke(hook, [])

        assert result.exit_code == 0
        context.output.deny.assert_not_called()
        context.output.exit_success.assert_called_once()

    @patch("ccguardian.cli.hook_command.ConfigurationManager")
    @patch("ccguardian.cli.hook_command.safe_create_context")
    def test_hook_valid_command_with_rules_exits_success(
        self, mock_safe_create_context, mock_config_manager
    ):
        context = pre_use_bash_context("ls -la")
        mock_safe_create_context.return_value = context

        grep_rule = PreUseBashRule(
            id="performance.grep_suggestion",
            enabled=True,
            priority=50,
            commands=[
                CommandPattern(
                    pattern=r"^grep\b(?!.*\|)",
                    action=Action.DENY,
                    message="Use 'rg' instead",
                )
            ],
        )
        mock_config = Mock()
        mock_config.active_rules = [grep_rule]
        mock_config_manager.return_value.load_configuration.return_value = mock_config

        result = self.runner.invoke(hook, [])

        assert result.exit_code == 0
        context.output.deny.assert_not_called()
        context.output.exit_success.assert_called_once()

    @patch("ccguardian.cli.hook_command.ConfigurationManager")
    @patch("ccguardian.cli.hook_command.safe_create_context")
    def test_hook_command_matching_deny_rule(self, mock_safe_create_context, mock_config_manager):
        context = pre_use_bash_context("test_command arg")
        mock_safe_create_context.return_value = context

        test_rule = PreUseBashRule(
            id="test.deny_rule",
            enabled=True,
            priority=50,
            commands=[
                CommandPattern(
                    pattern=r"^test_command\b",
                    action=Action.DENY,
                    message="Custom denial message for testing",
                )
            ],
        )
        mock_config = Mock()
        mock_config.active_rules = [test_rule]
        mock_config_manager.return_value.load_configuration.return_value = mock_config

        result = self.runner.invoke(hook, [])

        assert result.exit_code == 0
        context.output.deny.assert_called_once()
        call_args = context.output.deny.call_args[0][0]
        assert "Custom denial message for testing" in call_args

    @patch("ccguardian.cli.hook_command.exit_success")
    @patch("ccguardian.cli.hook_command.ConfigurationManager")
    @patch("ccguardian.cli.hook_command.safe_create_context")
    def test_hook_non_pretooluse_context_does_nothing(
        self, mock_safe_create_context, mock_config_manager, mock_exit_success
    ):
        post_tool_context = post_use_write_context("/tmp/test.txt", "test content")
        mock_safe_create_context.return_value = post_tool_context

        mock_config = Mock()
        mock_config.active_rules = []
        mock_config_manager.return_value.load_configuration.return_value = mock_config

        result = self.runner.invoke(hook, [])

        assert result.exit_code == 0
        mock_exit_success.assert_called_once()

    @patch("ccguardian.cli.hook_command.exit_non_block")
    @patch("ccguardian.cli.hook_command.ConfigurationManager")
    @patch("ccguardian.cli.hook_command.safe_create_context")
    def test_hook_exception_handling(
        self, mock_safe_create_context, mock_config_manager, mock_exit_non_block
    ):
        test_context = pre_use_bash_context("test command")
        mock_safe_create_context.return_value = test_context

        mock_config_manager.side_effect = Exception("Configuration loading failed")

        result = self.runner.invoke(hook, [])

        assert result.exit_code == 0
        mock_exit_non_block.assert_called_once()
        call_args = mock_exit_non_block.call_args[0][0]
        assert "Claude Code Guardian hook failed:" in call_args
        assert "Configuration loading failed" in call_args


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
