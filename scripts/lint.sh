#!/usr/bin/env bash

set -e
set -x

# uv run mypy ccguardian tests
uv run ruff check ccguardian tests
uv run ruff format ccguardian tests --check
