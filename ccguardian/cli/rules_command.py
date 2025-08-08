"""Rules command implementation with CLI-specific formatting logic."""

import logging

import click

from ..config import ConfigurationManager, ConfigValidationError
from ..rules import PathAccessRule, PreUseBashRule, Rule
from ..utils import setup_logging

logger = logging.getLogger(__name__)


def _get_configuration_sources_display(config_manager: ConfigurationManager) -> list[str]:
    """
    Get configuration source paths formatted for CLI display.

    Args:
        config_manager: ConfigurationManager instance

    Returns:
        List of formatted configuration source strings with existence status
    """
    import os

    sources = config_manager.loader.discover_all_sources()
    result = []

    for source in sources:
        status = "✓" if source.exists else "✗"
        result.append(f"{status} {source.display_name}: {source.path}")

    env_var = os.getenv("CLAUDE_CODE_GUARDIAN_CONFIG")
    if env_var:
        result.append(f"✓ Environment: CLAUDE_CODE_GUARDIAN_CONFIG={env_var}")
    else:
        result.append("✗ Environment: CLAUDE_CODE_GUARDIAN_CONFIG (not set)")

    return result


def _format_pre_use_bash_rule(rule: PreUseBashRule) -> list[str]:
    """Format a PreUseBashRule for display."""
    lines = []
    lines.append("Commands:")
    for cmd_pattern in rule.commands:
        action = cmd_pattern.action if cmd_pattern.action else rule.action
        lines.append(f"- `{cmd_pattern.pattern}` (action: {action.value})")
    return lines


def _format_path_access_rule(rule: PathAccessRule) -> list[str]:
    """Format a PathAccessRule for display."""
    lines = []
    lines.append("Paths:")
    for path_pattern in rule.paths:
        scope = path_pattern.scope if path_pattern.scope else rule.scope
        action = path_pattern.action if path_pattern.action else rule.action
        lines.append(f"- `{path_pattern.pattern}` [{scope.value}] (action: {action.value})")
    return lines


def format_rule(rule: Rule) -> list[str]:
    """Format a rule for display."""
    lines = []

    lines.append(f"ID: {rule.id} | Type: {rule.type} | Priority: {rule.priority}")
    match rule:
        case PreUseBashRule():
            lines.extend(_format_pre_use_bash_rule(rule))
        case PathAccessRule():
            lines.extend(_format_path_access_rule(rule))

    lines.append("")
    return lines


def format_rules_output(config_manager: ConfigurationManager) -> str:
    """
    Format complete rules diagnostic output for CLI display.

    Args:
        config_manager: ConfigurationManager instance

    Returns:
        Formatted string ready for CLI output
    """
    config = config_manager.load_configuration()
    sources_display = _get_configuration_sources_display(config_manager)

    lines = []

    lines.append("Configuration Sources:")
    for source_line in sources_display:
        lines.append(source_line)
    lines.append("")

    lines.append("Merged Configuration:")
    lines.append("=" * 20)

    if config.default_rules_enabled:
        if config.default_rules_patterns:
            patterns_str = ", ".join(config.default_rules_patterns)
            lines.append(f"Default Rules: enabled (patterns: {patterns_str})")
        else:
            lines.append("Default Rules: enabled")
    else:
        lines.append("Default Rules: disabled")

    lines.append(f"Total Rules: {config.total_rules}")
    lines.append(
        f"Active Rules: {len(config.active_rules)} ({len(config.disabled_rules)} disabled)"
    )
    lines.append("")

    if config.active_rules:
        lines.append("Rule Evaluation Order (by priority):")
        lines.append("=" * 35)
        lines.append("")

        for rule in config.active_rules:
            lines.extend(format_rule(rule))

    if config.disabled_rules:
        lines.append("Disabled Rules:")
        lines.append("=" * 14)
        lines.append("")

        for rule in config.disabled_rules:
            lines.append(f"ID: {rule.id} | Type: {rule.type}")

        lines.append("")

    return "\n".join(lines)


@click.command()
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose (debug) logging")
@click.help_option("-h", "--help")
def rules(verbose) -> None:
    """Display configuration diagnostics and rule information."""
    if verbose:
        setup_logging("DEBUG")

    logger.info("Executing rules command")

    try:
        config_manager = ConfigurationManager()
        output = format_rules_output(config_manager)
        click.echo(output)

    except ConfigValidationError as e:
        logger.error(f"Configuration validation failed: {e}")
        click.echo(f"Configuration Error: {e}", err=True)
        raise click.ClickException("Invalid configuration") from e
    except Exception as e:
        logger.error(f"Failed to load configuration: {e}")
        click.echo(f"Error: Failed to load configuration: {e}", err=True)
        raise click.ClickException("Configuration loading failed") from e
