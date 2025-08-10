"""Configuration merging logic for hierarchical configuration sources."""

import fnmatch
import logging
from typing import Any

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
        final_default_rules = True  # Default value

        for raw_config in raw_configs:
            sources.append(raw_config.source)
            # Later configs override default_rules setting
            if raw_config.data.default_rules is not None:
                final_default_rules = raw_config.data.default_rules

        default_rules_enabled, default_rules_patterns = self._process_default_rules(
            final_default_rules
        )

        merged_rules_data = self._merge_rules_by_id(
            raw_configs, default_rules_enabled, default_rules_patterns
        )
        rules = self.rule_factory.create_rules_from_merged_data(merged_rules_data)

        return Configuration(
            sources=sources,
            default_rules_enabled=default_rules_enabled,
            default_rules_patterns=default_rules_patterns,
            rules=rules,
        )

    def _process_default_rules(
        self, default_rules_setting: bool | list[str] | None
    ) -> tuple[bool, list[str] | None]:
        """
        Process default_rules configuration setting.

        Args:
            default_rules_setting: Value of default_rules from config (pre-validated)

        Returns:
            Tuple of (enabled, patterns) where:
            - enabled: True if any default rules should be included
            - patterns: None for all, or list of glob patterns to match
        """
        if default_rules_setting is None or default_rules_setting is True:
            return True, None
        elif default_rules_setting is False:
            return False, None
        elif isinstance(default_rules_setting, list):
            # Already validated by Pydantic to be list[str]
            return True, default_rules_setting
        else:
            # This shouldn't happen due to Pydantic validation, but handle gracefully
            return True, None

    def _merge_rules_by_id(
        self,
        raw_configs: list[RawConfiguration],
        default_rules_enabled: bool,
        default_rules_patterns: list[str] | None,
    ) -> dict[str, dict[str, Any]]:
        """
        Merge rules by ID across all configurations.

        Args:
            raw_configs: List of raw configurations
            default_rules_enabled: Whether default rules should be included
            default_rules_patterns: Patterns to match default rules (None = all)

        Returns:
            Dictionary mapping rule ID to merged rule data
        """
        merged_rules: dict[str, dict[str, Any]] = {}

        for raw_config in raw_configs:
            for rule_id, rule_config in raw_config.data.rules.items():
                if (
                    raw_config.source.source_type.value == "default"
                    and not self._should_include_default_rule(
                        rule_id, default_rules_enabled, default_rules_patterns
                    )
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
        self, rule_id: str, enabled: bool, patterns: list[str] | None
    ) -> bool:
        """
        Check if a default rule should be included based on filtering settings.

        Args:
            rule_id: Rule identifier to check
            enabled: Whether default rules are enabled at all
            patterns: Glob patterns to match (None = include all)

        Returns:
            True if rule should be included
        """
        if not enabled:
            return False

        if patterns is None:
            return True

        for pattern in patterns:
            if fnmatch.fnmatch(rule_id, pattern):
                return True

        return False

    def _merge_rule_config(
        self, target: dict[str, Any], source: dict[str, Any], rule_id: str, source_path
    ) -> None:
        """
        Merge source rule configuration into target rule.

        Simple merge strategy: later configurations override earlier ones.
        Type consistency is already enforced by validation.

        Args:
            target: Target rule configuration to merge into
            source: Source rule configuration to merge from
            rule_id: Rule ID for logging
            source_path: Source file path for logging
        """
        for key, value in source.items():
            # Only replace previous values if the new value is not None
            # This preserves hierarchical merging behavior
            if value is not None:
                target[key] = value
