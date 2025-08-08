"""Shared test utilities for creating mock contexts."""

from pathlib import Path
from unittest.mock import Mock

import yaml
from cchooks import PostToolUseContext, PreToolUseContext, SessionStartContext


def pre_use_context(tool_name: str, **tool_input) -> Mock:
    context = Mock(spec=PreToolUseContext)
    context.hook_event_name = "PreToolUse"
    context.tool_name = tool_name
    context.tool_input = tool_input
    context.output = Mock()
    context.output.exit_success = Mock()
    context.output.deny = Mock()
    context.session_id = "test-session-123"
    context._input_data = {"tool_name": tool_name, "tool_input": tool_input}
    return context


def pre_use_bash_context(command: str) -> Mock:
    return pre_use_context("Bash", command=command)


def pre_use_read_context(file_path: str) -> Mock:
    return pre_use_context("Read", file_path=file_path)


def pre_use_write_context(file_path: str, tool_name: str = "Write") -> Mock:
    return pre_use_context(tool_name, file_path=file_path)


def post_use_context(tool_name: str, tool_input: dict, tool_response: dict) -> Mock:
    context = Mock(spec=PostToolUseContext)
    context.hook_event_name = "PostToolUse"
    context.tool_name = tool_name
    context.tool_input = tool_input
    context.tool_response = tool_response
    context.output = Mock()
    context.output.exit_success = Mock()
    context.session_id = "test-session-123"
    context._input_data = {
        "tool_name": tool_name,
        "tool_input": tool_input,
        "tool_response": tool_response,
    }
    return context


def post_use_write_context(
    file_path: str, content: str = "file content", success: bool = True
) -> Mock:
    return post_use_context(
        "Write",
        tool_input={"file_path": file_path, "content": content},
        tool_response={"filePath": file_path, "success": success},
    )


def session_start_context(source: str = "startup") -> Mock:
    context = Mock(spec=SessionStartContext)
    context.hook_event_name = "SessionStart"
    context.source = source
    context.session_id = "test-session-123"
    context._input_data = {"source": source}
    return context


def create_yaml_config(config_dir: Path, filename: str, config_data: dict) -> Path:
    config_path = config_dir / filename
    config_path.parent.mkdir(parents=True, exist_ok=True)
    with open(config_path, "w") as f:
        yaml.dump(config_data, f)
    return config_path
