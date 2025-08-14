"""Rule factory for converting validated configuration to Python rule objects."""

import logging

from ..rules import (
    CommandPattern,
    PathAccessRule,
    PathPattern,
    PreUseBashRule,
    Rule,
)
from .models import PathAccessRuleConfig, PreUseBashRuleConfig, RuleConfigBase

logger = logging.getLogger(__name__)


class RuleFactory:
    """Factory for creating Rule objects from configuration data."""

    def create_rule(self, rule_id: str, rule_config: RuleConfigBase) -> Rule:
        """
        Create a Rule object from a validated Pydantic model instance.

        Args:
            rule_id: Unique identifier for the rule
            rule_config: Validated rule configuration model instance

        Returns:
            Rule object
        """
        match rule_config:
            case PreUseBashRuleConfig():
                return self._create_pre_use_bash_rule(rule_id, rule_config)
            case PathAccessRuleConfig():
                return self._create_path_access_rule(rule_id, rule_config)
            case RuleConfigBase():
                raise NotImplementedError(
                    f"Rule config type '{type(rule_config)}' is not implemented in factory"
                )

    def _create_pre_use_bash_rule(
        self, rule_id: str, config: PreUseBashRuleConfig
    ) -> PreUseBashRule:
        """Create a PreUseBashRule from validated Pydantic model."""
        # Convert Pydantic model command patterns to rule objects
        commands = []
        for cmd_pattern in config.commands:
            commands.append(
                CommandPattern(
                    pattern=cmd_pattern.pattern,
                    action=cmd_pattern.action,
                    message=cmd_pattern.message,
                )
            )

        return PreUseBashRule(
            id=rule_id,
            commands=commands,
            enabled=config.enabled if config.enabled is not None else True,
            priority=config.priority,
            action=config.action,
            message=config.message,
        )

    def _create_path_access_rule(
        self, rule_id: str, config: PathAccessRuleConfig
    ) -> PathAccessRule:
        """Create a PathAccessRule from validated Pydantic model."""
        # Convert Pydantic model path patterns to rule objects
        paths = []
        for path_pattern in config.paths:
            paths.append(
                PathPattern(
                    pattern=path_pattern.pattern,
                    scope=path_pattern.scope,
                    action=path_pattern.action,
                    message=path_pattern.message,
                )
            )

        return PathAccessRule(
            id=rule_id,
            paths=paths,
            enabled=config.enabled if config.enabled is not None else True,
            priority=config.priority,
            action=config.action,
            message=config.message,
            scope=config.scope,
        )

    def create_rules_from_merged_data(
        self, merged_rules_data: dict[str, RuleConfigBase]
    ) -> list[Rule]:
        """
        Create a list of Rule objects from validated merged configuration data.

        Args:
            merged_rules_data: Dictionary mapping rule ID to validated rule configuration instances

        Returns:
            List of Rule objects, sorted by priority (descending)
        """
        rules = [
            self.create_rule(rule_id, rule_config)
            for rule_id, rule_config in merged_rules_data.items()
        ]

        # Sort by priority (higher first), then by rule ID for deterministic ordering
        rules.sort(key=lambda r: (-r.priority, r.id))

        return rules
