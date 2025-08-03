"""Integration tests for the CLI."""

import json
import subprocess
import sys
from pathlib import Path


class TestCLIIntegration:
    """Test real CLI integration via subprocess."""

    def test_cli_no_args_exit_code(self):
        """Test that CLI exits with code 1 when no arguments provided."""
        result = subprocess.run(
            [sys.executable, "-m", "ccguardian.cli"],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 1
        assert "Claude Code Guardian" in result.stdout


class TestHookCommandIntegration:
    """Test real hook integration via subprocess with JSON input."""

    def test_hook_command_via_subprocess_grep_denial(self):
        """Test hook command via subprocess with grep command denial."""
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
        )

        # Hook should complete successfully (exit code 0)
        assert result.returncode == 0
        # Should output denial message to stderr (hook context output)
        assert "rg" in result.stderr or "rg" in result.stdout

    def test_hook_command_via_subprocess_safe_command(self):
        """Test hook command via subprocess with safe command that passes."""
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
        )

        # Hook should complete successfully
        assert result.returncode == 0
        # Should not output denial messages
        assert "rg" not in result.stderr
        assert "rg" not in result.stdout
