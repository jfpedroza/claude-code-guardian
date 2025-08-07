"""Hook command implementation for Claude Code Guardian."""

import logging

import click
from cchooks import PreToolUseContext, exit_non_block, exit_success, safe_create_context

from ..config.manager import ConfigurationManager
from ..rules import Action, Context, RuleResult

logger = logging.getLogger(__name__)


def _evaluate_rules(context: Context, rules: list) -> RuleResult | None:
    """Evaluate all rules against the context and return first matching result."""
    for rule in rules:
        result = rule.evaluate(context)
        if result:
            logger.debug(f"Rule {rule.id} matched: {result.action.value} - {result.message}")
            return result
    return None


@click.command()
def hook():
    """Claude Code hook entry point - validates tool usage using configuration rules."""
    context = None
    try:
        context = safe_create_context()
        logger.debug(f"Created hook context: {type(context).__name__}")

        config_manager = ConfigurationManager()
        config = config_manager.load_configuration()

        logger.debug(f"Evaluating {len(config.active_rules)} active rules")

        result = _evaluate_rules(context, config.active_rules)
        match context:
            case PreToolUseContext():
                if result and result.action == Action.DENY:
                    logger.info(f"Denying tool use: {result.message}")
                    context.output.deny(result.message)
                else:
                    logger.debug("Allowing tool use")
                    context.output.exit_success()
            case _:
                logger.warning(f"Unsupported context type: {type(context).__name__}")
                exit_success()

    except Exception as e:
        logger.error(f"Hook execution failed: {e}")
        exit_non_block(f"Claude Code Guardian hook failed: {e}")
