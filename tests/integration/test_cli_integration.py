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
    def test_hook_command_via_subprocess_session_start(self):
        hook_input = {
            "session_id": "test123",
            "transcript_path": "/tmp/test.jsonl",
            "cwd": str(Path.cwd()),
            "hook_event_name": "SessionStart",
            "source": "resume",
        }

        result = subprocess.run(
            [sys.executable, "-m", "ccguardian.cli", "hook"],
            input=json.dumps(hook_input),
            capture_output=True,
            text=True,
            env=_get_clean_env(),
        )

        assert result.returncode == 0
        assert result.stdout == ""
        assert result.stderr == ""

    def test_hook_command_via_subprocess_matching_rule(self):
        hook_input = {
            "session_id": "test123",
            "transcript_path": "/tmp/test.jsonl",
            "cwd": str(Path.cwd()),
            "hook_event_name": "PreToolUse",
            "tool_name": "Write",
            "tool_input": {"file_path": "/path/to/.git/file", "content": "something"},
        }

        result = subprocess.run(
            [sys.executable, "-m", "ccguardian.cli", "hook"],
            input=json.dumps(hook_input),
            capture_output=True,
            text=True,
            env=_get_clean_env(),
        )

        assert result.returncode == 0
        assert "Action denied. Rule security.git_access matched" in result.stdout
        assert result.stderr == ""

    def test_hook_command_via_subprocess_no_matching_rule(self):
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
        assert result.stdout == ""
        assert result.stderr == ""

    def test_hook_command_with_custom_configuration(self):
        custom_config = """
default_rules: false

rules:
  test.custom_rule:
    type: pre_use_bash
    pattern: "^echo.*test"
    action: warn
    message: "Custom test rule triggered"
    priority: 10
    enabled: true

  test.file_access:
    type: path_access
    pattern: "*.test"
    scope: read
    action: allow
    message: "Access to .test file"
    priority: 20
    enabled: false
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

            assert result.returncode == 1
            assert "Warning" in result.stderr
            assert "Custom test rule triggered" in result.stderr
            assert result.stdout == ""

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
            assert result.stdout == ""
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

        assert "security.git_access" in result.stdout
        assert "security.git_commands" in result.stdout
        assert "performance.grep_suggestion" in result.stdout
        assert "performance.find_suggestion" in result.stdout

        assert "Type: pre_use_bash" in result.stdout
        assert "Priority: 30" in result.stdout
        assert "Commands:" in result.stdout
        assert "action: deny" in result.stdout
