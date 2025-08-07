"""Pytest configuration and shared fixtures."""

import tempfile
from pathlib import Path
from unittest.mock import Mock

import pytest

from tests.utils import pre_use_bash_context, pre_use_write_context


@pytest.fixture
def mock_pretool_context():
    return pre_use_bash_context("ls -la")


@pytest.fixture
def mock_pretool_context_non_bash():
    return pre_use_write_context("/tmp/test.txt", "Edit")


@pytest.fixture
def mock_config_manager():
    mock_config = Mock()
    mock_config.rules = []
    mock_manager = Mock()
    mock_manager.load_configuration.return_value = mock_config
    return mock_manager


@pytest.fixture
def temp_config_dir():
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def sample_config_data():
    return {
        "default_rules": True,
        "rules": {
            "test.rule": {
                "type": "pre_use_bash",
                "pattern": "test_pattern",
                "action": "allow",
                "priority": 50,
                "enabled": True,
            }
        },
    }
