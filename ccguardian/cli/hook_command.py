"""Hook command implementation for Claude Code Guardian."""

import logging

import click
from cchooks import (
    HookContext,
    PostToolUseContext,
    PreCompactContext,
    PreToolUseContext,
    SessionStartContext,
    create_context,
    handle_context_error,
)

from ccguardian.engine import Engine

from ..utils import setup_logging

logger = logging.getLogger(__name__)


def _context_suffix(context: HookContext) -> str | None:
    match context:
        case PreToolUseContext() | PostToolUseContext():
            return context.tool_name
        case PreCompactContext():
            return context.trigger
        case SessionStartContext():
            return context.source


@click.command()
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose (debug) logging")
@click.help_option("-h", "--help")
def hook(verbose):
    """Claude Code hook entry point - set in CC settings.json."""
    if verbose:
        setup_logging("DEBUG")

    try:
        context = create_context()
        context_suffix = _context_suffix(context)
        if context_suffix:
            hook_name = f"{context.hook_event_name}:{context_suffix}"
        else:
            hook_name = context.hook_event_name

        logger.info(f"Executing hook for {hook_name}. Session ID: {context.session_id}")
        logger.debug(f"Hook input data: {context._input_data}")

        engine = Engine(context)
        engine.run()
    except Exception as e:
        logger.error(f"Hook context creation failed: {e}", exc_info=True)
        handle_context_error(e)
