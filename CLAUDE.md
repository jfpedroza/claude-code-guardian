# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Claude Code Guardian** is a comprehensive validation framework for Claude Code that provides security,
performance, and policy enforcement. The project validates Claude Code tool usage and provides suggestions for
better alternatives.

Currently in early development.

## Architecture

### Package Structure

The project follows a modular architecture:

- **`ccguardian/cli/`**: CLI commands and entry points
  - `main.py`: Primary CLI group with help system
  - `hook_command.py`: Hook validation command for Claude Code integration
  - `rules_command.py`: Rule management and display commands
- **`ccguardian/config/`**: Configuration management system
  - `types.py`: Core data classes (Configuration, Rule, SourceType)
  - `manager.py`: Configuration loading and merging orchestration
  - `loader.py`: YAML configuration file parsing
  - `factory.py`: Configuration source discovery and creation
  - `merger.py`: Multi-source configuration merging logic
  - `default.yml`: Built-in default rules
- **`ccguardian/rules.py`**: Rule definitions and validation logic

### Hook Integration

Uses cchooks library for Claude Code hook contexts. The system intercepts tool usage events
and applies validation rules before execution.

## Development Commands

### Package Management

```bash
# Install dependencies
uv sync

# Build and install package locally
uv sync  # Automatically builds due to tool.uv.package = true
```

### CLI Usage

```bash
# Show help (exits with code 1 when no args)
uv run claude-code-guardian
uv run claude-code-guardian -h
uv run claude-code-guardian --help

# Execute hook validation (main entry point for Claude Code)
uv run claude-code-guardian hook
```

### Testing

```bash
# Run all tests with coverage (default configuration)
uv run pytest

# Run tests without coverage  
uv run pytest --no-cov

# Run specific test files
uv run pytest tests/unit/test_cli.py
uv run pytest tests/unit/test_config_factory.py
uv run pytest tests/integration/

# Run tests with verbose output
uv run pytest -v

# Test CLI functionality manually
uv run claude-code-guardian  # Should show help and exit code 1
uv run claude-code-guardian hook --help
uv run claude-code-guardian rules

# Test CLI as if installed with a built package
uvx --no-cache --from /path/to/claude-code-guardian claude-code-guardian <args>
```

### Code Quality

```bash
# Check lint and formatting issues
scripts/lint.sh

# Fix formatting issues automatically
scripts/format.sh
```

**REQUIRED**: After editing code files, IMMEDIATELY run `scripts/format.sh` before proceeding

**Test Structure:**

- `tests/unit/` - Unit tests
- `tests/integration/` - Integration tests
- `tests/conftest.py` - Shared fixtures and mock contexts

## Configuration

### Project Configuration

- **Package Name**: `claude-code-guardian` (CLI command name)
- **Python Package**: `ccguardian` (internal package name)
- **Python Version**: `>=3.12`
- **Dependencies**: `cchooks`, `click`, `PyYAML`
- **Dev Dependencies**: `ruff`, `mypy`, `pytest`

### Configuration System

The application supports a hierarchical configuration system with multiple sources:

1. **Default rules**: Built-in rules from `ccguardian/config/default.yml`
2. **User config**: `~/.config/claude-code-guardian/config.yml`
3. **Shared config**: `/etc/claude-code-guardian/config.yml`
4. **Local config**: `.claude-code-guardian.yml` in project root

Configuration sources are merged with local taking highest priority. Each source can:

- Enable/disable default rules
- Define custom validation rules
- Set rule priorities and patterns

### Test Coverage Requirements

- **Minimum Coverage**: 80% (enforced by pytest-cov)
- **Coverage Reports**: Terminal, HTML (htmlcov/), and XML formats
- **Branch Coverage**: Enabled for comprehensive testing

## Guidelines to follow at all times

- Always keep your changes limited to what was explicitly mentioned
- Don't use any 3rd party libraries/framework/code unless explicitly requested
- Focus on simplicity both in terms of design/architecture and implementation
- Code has to be easy to reason about, and easy to extend/change in the future
- Validate that you understand the question correctly by re-iterating what's asked of you but with different words
- Double-check your work before committing, think outside the box and consider tradeoffs and pros/cons.
- Consider how maintainable your changes will be, always try to create as maintainable code as possible
- Take a step back if needed and retry if you can think of a better solution
- Simple is better than complicated
- All code should be treated as production code
- Don't add any comments unless the next line is really complicated and hard to understand
- Don't create new abstractions unless absolutely required for fulfilling what's outlined above
- Most important, try to write simple and easily understood code
