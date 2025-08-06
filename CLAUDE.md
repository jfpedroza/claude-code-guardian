# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Claude Code Guardian** is a comprehensive validation framework for Claude Code that provides security,
performance, and policy enforcement. The project validates Claude Code tool usage and provides suggestions for
better alternatives.

Currently in early development.

## Architecture

### Current State

- **CLI Entry Point**: `claude-code-guardian` command with `hook` subcommand
- **Package Structure**: `ccguardian/` package with `cli.py` as main module
- **Hook Integration**: Uses `cchooks>=0.1.2` library for Claude Code hook contexts

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
# Run all tests with coverage
uv run pytest

# Run tests without coverage  
uv run pytest --no-cov

# Run specific test files
uv run pytest tests/unit/test_cli.py
uv run pytest tests/unit/test_validation_rules.py
uv run pytest tests/integration/

# Run tests with verbose output
uv run pytest -v

# Test CLI functionality manually
uv run claude-code-guardian  # Should show help and exit code 1
uv run claude-code-guardian hook --help

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

**IMPORTANT**: Always run format.sh after making code changes

**Test Structure:**

- `tests/unit/` - Unit tests
- `tests/integration/` - Integration tests
- `tests/conftest.py` - Shared fixtures and mock contexts

## Configuration

### Project Configuration

- **Package Name**: `claude-code-guardian` (CLI command name)
- **Python Package**: `ccguardian` (internal package name)
- **Python Version**: `>=3.12`
- **Dependencies**: `cchooks>=0.1.2`, `click>=8.0.0`

### Current Validation Rules

Located in `ccguardian/cli.py` as `_VALIDATION_RULES`:

1. **grep optimization**: Suggests `rg` instead of `grep` for better performance
2. **find optimization**: Suggests `rg --files | rg pattern` instead of `find -name`

## Code Style Guidelines

- Do not add superflous comments