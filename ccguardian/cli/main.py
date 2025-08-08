"""Main CLI entry point for Claude Code Guardian."""

import sys

import click

from ..utils import setup_logging
from .hook_command import hook
from .rules_command import rules


@click.group(invoke_without_command=True)
@click.pass_context
@click.help_option("-h", "--help")
def main(ctx):
    """Claude Code Guardian - Validation rules for tool usage and file access for Claude Code."""
    setup_logging()

    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())
        sys.exit(1)


main.add_command(hook)
main.add_command(rules)
