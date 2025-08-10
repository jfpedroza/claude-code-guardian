"""Rule factory for converting validated configuration to Python rule objects."""

import logging
from typing import Any

from ..rules import (
    DEFAULT_PRIORITY,
    Action,
    CommandPattern,
    PathAccessRule,
    PathPattern,
    PreUseBashRule,
    Rule,
    Scope,
)
from .exceptions import ConfigValidationError

logger = logging.getLogger(__name__)


class RuleFactory:
    """Factory for creating Rule objects from configuration data."""

    def create_rule(self, rule_id: str, rule_config: dict[str, Any]) -> Rule:
        """
        Create a Rule object from pre-validated configuration data.

        Args:
            rule_id: Unique identifier for the rule
            rule_config: Dictionary containing validated rule configuration

        Returns:
            Rule object
        """
        # Configuration is pre-validated, so we can trust the data
        rule_type = rule_config["type"]  # Required field, guaranteed to exist and be valid

        if rule_type == PreUseBashRule.type:
            return self._create_pre_use_bash_rule(rule_id, rule_config)
        elif rule_type == PathAccessRule.type:
            return self._create_path_access_rule(rule_id, rule_config)
        else:
            # This shouldn't happen with validated data, but handle gracefully
            raise ConfigValidationError(
                f"Unsupported rule type '{rule_type}' in factory", rule_id=rule_id
            )

    def _create_pre_use_bash_rule(self, rule_id: str, config: dict[str, Any]) -> PreUseBashRule:
        """Create a PreUseBashRule from pre-validated configuration."""
        # Configuration is pre-validated and contains commands list
        commands_data = config["commands"]  # Guaranteed to exist by validation

        # Convert command dictionaries to CommandPattern objects
        commands = []
        for cmd_data in commands_data:
            commands.append(
                CommandPattern(
                    pattern=cmd_data["pattern"],
                    action=Action(cmd_data["action"]) if cmd_data.get("action") else None,
                    message=cmd_data.get("message"),
                )
            )

        return PreUseBashRule(
            id=rule_id,
            commands=commands,
            enabled=config.get("enabled", True),
            priority=config.get("priority", DEFAULT_PRIORITY),
            action=Action(config["action"]) if config.get("action") else None,
            message=config.get("message"),
        )

    def _create_path_access_rule(self, rule_id: str, config: dict[str, Any]) -> PathAccessRule:
        """Create a PathAccessRule from pre-validated configuration."""
        # Configuration is pre-validated and contains paths list
        paths_data = config["paths"]  # Guaranteed to exist by validation

        # Convert path dictionaries to PathPattern objects
        paths = []
        for path_data in paths_data:
            paths.append(
                PathPattern(
                    pattern=path_data["pattern"],
                    scope=Scope(path_data["scope"]) if path_data.get("scope") else None,
                    action=Action(path_data["action"]) if path_data.get("action") else None,
                    message=path_data.get("message"),
                )
            )

        return PathAccessRule(
            id=rule_id,
            paths=paths,
            enabled=config.get("enabled", True),
            priority=config.get("priority", DEFAULT_PRIORITY),
            action=Action(config["action"]) if config.get("action") else None,
            message=config.get("message"),
            scope=Scope(config["scope"]) if config.get("scope") else None,
        )


    def create_rules_from_merged_data(
        self, merged_rules_data: dict[str, dict[str, Any]]
    ) -> list[Rule]:
        """
        Create a list of Rule objects from pre-validated merged configuration data.

        Args:
            merged_rules_data: Dictionary mapping rule ID to validated rule configuration

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
