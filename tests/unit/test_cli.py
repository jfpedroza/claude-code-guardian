"""Tests for CLI functionality."""

import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from click.testing import CliRunner

from ccguardian.cli import main
from ccguardian.cli.hook_command import hook
from ccguardian.cli.rules_command import rules
from tests.utils import pre_use_bash_context


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
        assert "you forgot the hook argument" in result.stderr

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

    @patch("ccguardian.cli.hook_command.Engine")
    @patch("ccguardian.cli.hook_command.create_context")
    def test_hook_runs_engine(self, mock_create_context, mock_engine):
        context = pre_use_bash_context("ls -la")
        mock_create_context.return_value = context
        mock_engine_instance = Mock()
        mock_engine.return_value = mock_engine_instance

        result = self.runner.invoke(hook, [])

        assert result.exit_code == 0
        mock_engine.assert_called_once_with(context)
        mock_engine_instance.run.assert_called_once()

    @patch("ccguardian.cli.hook_command.handle_context_error")
    @patch("ccguardian.cli.hook_command.create_context")
    def test_hook_exception_handling(self, mock_create_context, mock_handle_context_error):
        mock_create_context.side_effect = Exception("Context creation failed")

        result = self.runner.invoke(hook, [])

        assert result.exit_code == 0
        mock_handle_context_error.assert_called_once()


class TestRulesCommand:
    def setup_method(self):
        self.runner = CliRunner()

    def test_rules_help(self):
        result = self.runner.invoke(main, ["rules", "--help"])

        assert result.exit_code == 0
        assert "Display configuration diagnostics and rule information" in result.output

    def test_rules_command_integration(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create empty temporary directories to isolate from user configs
            user_dir = Path(tmpdir) / "user_config"
            project_dir = Path(tmpdir) / "project"
            user_dir.mkdir()
            project_dir.mkdir()

            with patch.dict(
                "os.environ",
                {
                    "CLAUDE_CODE_GUARDIAN_CONFIG": str(user_dir),
                    "CLAUDE_PROJECT_DIR": str(project_dir),
                },
                clear=False,
            ):
                result = self.runner.invoke(rules, [])

                assert result.exit_code == 0

                assert "Configuration Sources:" in result.output
                assert "✓ Default:" in result.output
                assert "✗ User:" in result.output
                assert "✗ Shared:" in result.output
                assert "✗ Local:" in result.output
                assert "✓ Environment: CLAUDE_CODE_GUARDIAN_CONFIG" in result.output

                assert "Merged Configuration:" in result.output
                assert "Default Rules: enabled" in result.output
                assert "Total Rules:" in result.output
                assert "Active Rules:" in result.output

                assert "Rule Evaluation Order (by priority):" in result.output
                assert "security.git_access" in result.output
                assert "security.git_commands" in result.output
                assert "Type: pre_use_bash" in result.output
                assert "Priority: 30" in result.output

                assert "Commands:" in result.output
                assert "action: deny" in result.output

    def test_rules_command_with_env_var(self):
        import os
        from unittest.mock import patch

        with patch.dict(os.environ, {"CLAUDE_CODE_GUARDIAN_CONFIG": "/tmp/custom"}):
            result = self.runner.invoke(rules, [])

        assert result.exit_code == 0
        assert "✓ Environment: CLAUDE_CODE_GUARDIAN_CONFIG=/tmp/custom" in result.output
