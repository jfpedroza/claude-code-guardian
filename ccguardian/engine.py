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

        log_message = f"Rule {result.rule_id} matched with message: {result.message}"
        user_message = f"{result.message} (Rule: {result.rule_id})"

        match result.action:
            case Action.ALLOW:
                logger.info(f"Action allowed. {log_message}")
                self.context.output.allow(f"Guardian: Action allowed. {user_message}")
                exit_success()
            case Action.WARN:
                logger.warning(f"Warning. {log_message}")
                self.context.output.allow(system_message=f"Guardian: {user_message}")
                exit_success()
            case Action.ASK:
                logger.info(f"Asking the user. {log_message}")
                self.context.output.ask(f"Guardian: {user_message}")
                exit_success()
            case Action.DENY:
                logger.warning(f"Action denied. {log_message}")
                self.context.output.deny(f"Guardian: {user_message}")
                exit_success()
            case Action.HALT:
                logger.error(f"Halting. {log_message}")
                self.context.output.halt(f"Guardian: 🛑 Halting. {user_message}")
                exit_success()
            case Action.CONTINUE:
                logger.info(f"Continuing with CC's default permissions. {log_message}")
                exit_success()
