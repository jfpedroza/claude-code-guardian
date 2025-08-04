"""Pytest configuration and shared fixtures."""

import pytest

from tests.utils import pre_use_bash_context, pre_use_write_context


@pytest.fixture
def mock_pretool_context():
    """Create a mock PreToolUse context for testing."""
    return pre_use_bash_context("ls -la")


@pytest.fixture
def mock_pretool_context_non_bash():
    """Create a mock PreToolUse context for non-Bash tools."""
    return pre_use_write_context("/tmp/test.txt", "Edit")
