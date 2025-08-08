import logging
from typing import NoReturn

from cchooks import (
    HookContext,
    PreToolUseContext,
    SessionStartContext,
    exit_non_block,
    exit_success,
)

from ccguardian.config import Configuration, ConfigurationManager, ConfigValidationError
from ccguardian.rules import Action, Rule, RuleResult

logger = logging.getLogger(__name__)


class Engine:
    context: HookContext
    config: Configuration | None

    def __init__(self, context: HookContext) -> None:
        self.context = context

    def run(self) -> NoReturn:
        try:
            match self.context:
                case SessionStartContext():
                    config_manager = ConfigurationManager()
                    config_manager.load_configuration()
                    exit_success()

                case PreToolUseContext():
                    config_manager = ConfigurationManager()
                    config = config_manager.load_configuration()

                    logger.debug(f"Evaluating {len(config.active_rules)} active rules")

                    result = self.evaluate_rules(config.active_rules)
                    self.handle_result(result)
                case _:
                    exit_success()

        except ConfigValidationError as e:
            logger.error(f"Configuration validation failed: {e}")
            exit_non_block(f"Claude Code Guardian configuration error: {e}")
        except Exception as e:
            logger.error(f"Hook execution failed: {e}", exc_info=True)
            exit_non_block(f"Claude Code Guardian hook failed: {e}")

    def evaluate_rules(self, rules: list[Rule]) -> RuleResult | None:
        """Evaluate all rules against the context and return first matching result."""
        for rule in rules:
            result = rule.evaluate(self.context)
            if result:
                logger.debug(f"Rule {rule.id} matched: {result.action.value} - {result.message}")
                return result
        return None

    def handle_result(self, result: RuleResult | None) -> NoReturn:
        if result is None:
            logger.info("No rule matches. No action taken")
            exit_success()

        assert isinstance(self.context, PreToolUseContext)

        rule_message = f"Rule {result.rule_id} matched with message: {result.message}"

        match result.action:
            case Action.ALLOW:
                reason = f"Action allowed. {rule_message}"
                logger.info(reason)
                self.context.output.allow(reason)
                exit_success()
            case Action.WARN:
                reason = f"Warning. {rule_message}"
                logger.warning(reason)
                exit_non_block(reason)
            case Action.ASK:
                reason = f"Asking the user. {rule_message}"
                logger.info(reason)
                self.context.output.ask(reason)
                exit_success()
            case Action.DENY:
                reason = f"Action denied. {rule_message}"
                logger.warning(reason)
                self.context.output.deny(reason)
                exit_success()
            case Action.HALT:
                reason = f"Halting. {rule_message}"
                logger.error(reason)
                self.context.output.halt(reason)
                exit_success()
            case Action.CONTINUE:
                reason = f"Continuing with CC's default permissions. {rule_message}"
                logger.info(reason)
                exit_success()
