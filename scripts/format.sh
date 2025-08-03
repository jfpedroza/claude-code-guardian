#!/bin/sh -e
set -x

uv run ruff check ccguardian tests --fix
uv run ruff format ccguardian tests
