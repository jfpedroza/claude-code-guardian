"""Pytest configuration and shared fixtures."""

import pytest
from unittest.mock import Mock
from cchooks import PreToolUseContext


@pytest.fixture
def mock_pretool_context():
    """Create a mock PreToolUse context for testing."""
    context = Mock(spec=PreToolUseContext)
    context.tool_name = "Bash"
    context.tool_input = {"command": "ls -la"}
    context.output = Mock()
    context.output.exit_success = Mock()
    context.output.deny = Mock()
    return context


@pytest.fixture
def mock_pretool_context_non_bash():
    """Create a mock PreToolUse context for non-Bash tools."""
    context = Mock(spec=PreToolUseContext)
    context.tool_name = "Edit"
    context.tool_input = {"file_path": "/tmp/test.txt"}
    context.output = Mock()
    context.output.exit_success = Mock()
    context.output.deny = Mock()
    return context
