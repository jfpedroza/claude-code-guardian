"""Configuration merging logic for hierarchical configuration sources."""

import fnmatch
import logging
from typing import Any

from .exceptions import ConfigValidationError
from .factory import RuleFactory
from .types import Configuration, RawConfiguration

logger = logging.getLogger(__name__)


class ConfigurationMerger:
    """Merges multiple configuration sources into a single configuration."""

    def __init__(self):
        """Initialize the merger with a rule factory."""
        self.rule_factory = RuleFactory()

    def merge_configurations(self, raw_configs: list[RawConfiguration]) -> Configuration:
        """
        Merge multiple raw configurations into a single configuration.

        Configuration hierarchy: default → user → shared → local
        Later configurations override earlier ones by rule ID.

        Args:
            raw_configs: List of raw configurations in hierarchical order

        Returns:
            Merged configuration
        """
        if not raw_configs:
            return Configuration()

        # Collect sources and the final default_rules setting
        sources = []
        final_default_rules: bool | list[str] = True  # Default value

        for raw_config in raw_configs:
            sources.append(raw_config.source)
            # Later configs override default_rules setting
            if raw_config.data.default_rules is not None:
                final_default_rules = raw_config.data.default_rules

        merged_rules_data = self._merge_rules_by_id(raw_configs, final_default_rules)
        rules = self.rule_factory.create_rules_from_merged_data(merged_rules_data)

        return Configuration(
            sources=sources,
            default_rules=final_default_rules,
            rules=rules,
        )

    def _merge_rules_by_id(
        self,
        raw_configs: list[RawConfiguration],
        default_rules_setting: bool | list[str],
    ) -> dict[str, dict[str, Any]]:
        """
        Merge rules by ID across all configurations.

        Args:
            raw_configs: List of raw configurations
            default_rules_setting: Default rules setting (True=all, False=none, list=patterns)

        Returns:
            Dictionary mapping rule ID to merged rule data
        """
        merged_rules: dict[str, dict[str, Any]] = {}

        for raw_config in raw_configs:
            for rule_id, rule_config in raw_config.data.rules.items():
                if (
                    raw_config.source.source_type.value == "default"
                    and not self._should_include_default_rule(rule_id, default_rules_setting)
                ):
                    continue

                if rule_id not in merged_rules:
                    merged_rules[rule_id] = {}

                # Convert model to dictionary for the factory
                # Handle both model objects and raw dictionaries
                if hasattr(rule_config, "model_dump"):
                    # Model object - serialize with enum string values
                    rule_dict = rule_config.model_dump(exclude_none=True, mode="json")
                else:
                    # Raw dictionary (partial config)
                    rule_dict = {k: v for k, v in rule_config.items() if v is not None}
                self._merge_rule_config(
                    merged_rules[rule_id], rule_dict, rule_id, raw_config.source.path
                )

        return merged_rules

    def _should_include_default_rule(
        self, rule_id: str, default_rules_setting: bool | list[str]
    ) -> bool:
        """
        Check if a default rule should be included based on filtering settings.

        Args:
            rule_id: Rule identifier to check
            default_rules_setting: Default rules setting (True=all, False=none, list=patterns)

        Returns:
            True if rule should be included
        """
        if default_rules_setting is False:
            return False

        if default_rules_setting is True:
            return True

        # default_rules_setting is a list of patterns
        for pattern in default_rules_setting:
            if fnmatch.fnmatch(rule_id, pattern):
                return True

        return False

    def _merge_rule_config(
        self, target: dict[str, Any], source: dict[str, Any], rule_id: str, source_path
    ) -> None:
        """
        Merge source rule configuration into target rule.

        Simple merge strategy: later configurations override earlier ones.
        The rule type field cannot be changed once set.

        Args:
            target: Target rule configuration to merge into
            source: Source rule configuration to merge from
            rule_id: Rule ID for logging
            source_path: Source file path for logging

        Raises:
            ConfigValidationError: If attempting to override rule type
        """
        for key, value in source.items():
            # Only replace previous values if the new value is not None
            # This preserves hierarchical merging behavior
            if value is not None:
                if key == "type" and key in target and target[key] != value:
                    raise ConfigValidationError(
                        f"Cannot change rule type from '{target[key]}' to '{value}'",
                        rule_id=rule_id,
                        source_path=str(source_path),
                    )
                target[key] = value
