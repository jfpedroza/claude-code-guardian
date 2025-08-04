"""Command-line interface for Claude Code Guardian."""

import sys

import click
from cchooks import PreToolUseContext, create_context

from .rules import Action, CommandPattern, Context, PreUseBashRule, RuleResult

# Define validation rules using the new rule classes
_VALIDATION_RULES = [
    PreUseBashRule(
        id="performance.grep_suggestion",
        commands=[
            CommandPattern(
                pattern=r"^grep\b(?!.*\|)",
                action=Action.DENY,
                message="Use 'rg' (ripgrep) instead of 'grep' for better performance and features",
            )
        ],
    ),
    PreUseBashRule(
        id="performance.find_suggestion",
        commands=[
            CommandPattern(
                pattern=r"^find\s+\S+\s+-name\b",
                action=Action.DENY,
                message="Use 'rg --files | rg pattern' or 'rg --files -g pattern' instead of 'find -name' for better performance",
            )
        ],
    ),
]


def _evaluate_rules(context: Context) -> RuleResult | None:
    """Evaluate all rules against the context and return deny message if any rule denies."""
    for rule in _VALIDATION_RULES:
        result = rule.evaluate(context)
        if result:
            return result
    return None


@click.group(invoke_without_command=True)
@click.pass_context
@click.help_option("-h", "--help")
def main(ctx):
    """Claude Code Guardian - Validation rules for tool usage and file access for Claude Code."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())
        sys.exit(1)


@main.command()
def hook():
    """Claude Code hook entry point"""
    c = create_context()

    result = _evaluate_rules(c)

    match c:
        case PreToolUseContext():
            if result and result.action == Action.DENY:
                c.output.deny(result.message)
            else:
                c.output.exit_success()


if __name__ == "__main__":
    main()
