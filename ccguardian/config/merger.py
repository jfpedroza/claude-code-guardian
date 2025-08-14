"""Configuration merging logic for hierarchical configuration sources."""

import fnmatch
import logging
from typing import Any

from pydantic import ValidationError

from .exceptions import ConfigValidationError
from .factory import RuleFactory
from .models import RuleConfigBase, validate_rule_config
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
    ) -> dict[str, RuleConfigBase]:
        """
        Merge rules by ID across all configurations and validate final results.

        Args:
            raw_configs: List of raw configurations
            default_rules_setting: Default rules setting (True=all, False=none, list=patterns)

        Returns:
            Dictionary mapping rule ID to validated rule configuration instances

        Raises:
            ConfigValidationError: If merged rule configurations are invalid
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

                # Convert model to dictionary for merging
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

        # Validate and convert merged configurations to typed instances
        return self._validate_merged_rules(merged_rules)

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

    def _validate_merged_rules(
        self, merged_rules: dict[str, dict[str, Any]]
    ) -> dict[str, RuleConfigBase]:
        """
        Validate merged rule configurations and convert to typed instances.

        Args:
            merged_rules: Dictionary of merged rule configurations

        Returns:
            Dictionary mapping rule ID to validated rule configuration instances

        Raises:
            ConfigValidationError: If any merged rule configuration is invalid
        """
        validated_rules: dict[str, RuleConfigBase] = {}

        for rule_id, rule_data in merged_rules.items():
            try:
                validated_rules[rule_id] = validate_rule_config(rule_data, rule_id)
            except ValidationError as e:
                # Convert Pydantic validation errors to ConfigValidationError
                error_details = []
                for error in e.errors():
                    location = (
                        " -> ".join(str(x) for x in error["loc"]) if error["loc"] else "root"
                    )
                    error_details.append(f"{location}: {error['msg']}")

                error_message = (
                    f"Merged rule configuration validation failed for rule '{rule_id}':\n"
                    + "\n".join(error_details)
                )
                raise ConfigValidationError(error_message, rule_id=rule_id) from e
            except ValueError as e:
                # Convert ValueError from validate_rule_config to ConfigValidationError
                raise ConfigValidationError(str(e), rule_id=rule_id) from e

        return validated_rules
