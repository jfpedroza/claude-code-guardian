"""Integration tests for the CLI."""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


def _get_clean_env():
    """Get environment variables with config paths pointing to empty directories."""
    env = os.environ.copy()
    temp_dir = tempfile.mkdtemp()
    user_dir = Path(temp_dir) / "user_config"
    project_dir = Path(temp_dir) / "project"

    user_dir.mkdir(parents=True)
    project_dir.mkdir(parents=True)

    env["CLAUDE_CODE_GUARDIAN_CONFIG"] = str(user_dir)
    env["CLAUDE_PROJECT_DIR"] = str(project_dir)
    return env


class TestCLIIntegration:
    def test_cli_no_args_exit_code(self):
        result = subprocess.run(
            [sys.executable, "-m", "ccguardian.cli"],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 1
        assert "Claude Code Guardian" in result.stdout
        assert "hook" in result.stdout
        assert "rules" in result.stdout
        assert "you forgot the hook argument" in result.stderr


class TestHookCommandIntegration:
    def test_hook_command_via_subprocess_grep_denial(self):
        hook_input = {
            "session_id": "test123",
            "transcript_path": "/tmp/test.jsonl",
            "cwd": str(Path.cwd()),
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "grep pattern file.txt"},
        }

        result = subprocess.run(
            [sys.executable, "-m", "ccguardian.cli", "hook"],
            input=json.dumps(hook_input),
            capture_output=True,
            text=True,
            env=_get_clean_env(),
        )

        assert result.returncode == 0
        assert "rg" in result.stdout
        assert result.stderr == ""

    def test_hook_command_via_subprocess_safe_command(self):
        hook_input = {
            "session_id": "test123",
            "transcript_path": "/tmp/test.jsonl",
            "cwd": str(Path.cwd()),
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "ls -la"},
        }

        result = subprocess.run(
            [sys.executable, "-m", "ccguardian.cli", "hook"],
            input=json.dumps(hook_input),
            capture_output=True,
            text=True,
            env=_get_clean_env(),
        )

        assert result.returncode == 0
        assert "rg" not in result.stdout
        assert result.stderr == ""

    def test_hook_command_with_custom_configuration(self):
        custom_config = """
default_rules: false

rules:
  test.custom_rule:
    type: pre_use_bash
    pattern: "^echo.*test"
    action: deny
    message: "Custom test rule triggered"
    priority: 10
    enabled: true
"""

        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = Path(tmpdir) / ".claude" / "guardian"
            config_dir.mkdir(parents=True)

            config_file = config_dir / "config.yml"
            config_file.write_text(custom_config)

            hook_input = {
                "session_id": "test123",
                "transcript_path": "/tmp/test.jsonl",
                "cwd": tmpdir,
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "echo something test"},
            }

            env = _get_clean_env()
            env["CLAUDE_PROJECT_DIR"] = tmpdir

            result = subprocess.run(
                [sys.executable, "-m", "ccguardian.cli", "hook"],
                input=json.dumps(hook_input),
                capture_output=True,
                text=True,
                env=env,
            )

            assert result.returncode == 0
            assert "Custom test rule triggered" in result.stdout
            assert result.stderr == ""

            # Test hook with command that doesn't match (should pass)
            hook_input["tool_input"]["command"] = "ls -la"

            result = subprocess.run(
                [sys.executable, "-m", "ccguardian.cli", "hook"],
                input=json.dumps(hook_input),
                capture_output=True,
                text=True,
                env=env,
            )

            assert result.returncode == 0
            assert "Custom test rule triggered" not in result.stdout
            assert "rg" not in result.stdout
            assert result.stderr == ""


class TestRulesCommandIntegration:
    """Integration tests for the rules command via subprocess."""

    def test_rules_command_via_subprocess(self):
        result = subprocess.run(
            [sys.executable, "-m", "ccguardian.cli", "rules"],
            capture_output=True,
            text=True,
            env=_get_clean_env(),
        )

        assert result.returncode == 0

        assert "Configuration Sources:" in result.stdout
        assert "Merged Configuration:" in result.stdout
        assert "Rule Evaluation Order" in result.stdout
        assert "Default Rules: enabled" in result.stdout

        assert "performance.grep_suggestion" in result.stdout
        assert "performance.find_suggestion" in result.stdout
        assert "security.git_access" in result.stdout

        assert "Type: pre_use_bash" in result.stdout
        assert "Priority: 50" in result.stdout
        assert "Commands:" in result.stdout
        assert "action: deny" in result.stdout
