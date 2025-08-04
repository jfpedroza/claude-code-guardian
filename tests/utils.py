"""Shared test utilities for creating mock contexts."""

from unittest.mock import Mock

from cchooks import PreToolUseContext


def pre_use_bash_context(command: str) -> Mock:
    """Create a mock PreToolUseContext for Bash tool with given command."""
    return pre_use_context("Bash", command=command)


def pre_use_read_context(file_path: str) -> Mock:
    """Create a mock PreToolUseContext for Read tool with given file path."""
    return pre_use_context("Read", file_path=file_path)


def pre_use_write_context(file_path: str, tool_name: str = "Write") -> Mock:
    """Create a mock PreToolUseContext for write tools with given file path."""
    return pre_use_context(tool_name, file_path=file_path)


def pre_use_context(tool_name: str, **tool_input) -> Mock:
    """Create a mock PreToolUseContext with given tool name and input."""
    context = Mock(spec=PreToolUseContext)
    context.tool_name = tool_name
    context.tool_input = tool_input
    context.output = Mock()
    context.output.exit_success = Mock()
    context.output.deny = Mock()
    return context
