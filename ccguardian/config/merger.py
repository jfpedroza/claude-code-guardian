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

        merged_data: dict[str, Any] = {}
        sources = []

        for raw_config in raw_configs:
            sources.append(raw_config.source)
            self._merge_config_data(merged_data, raw_config.data)

        default_rules_enabled, default_rules_patterns = self._process_default_rules(
            merged_data.get("default_rules", True)
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

    def _merge_config_data(self, target: dict[str, Any], source: dict[str, Any]) -> None:
        """
        Merge source configuration data into target.

        Simple merge strategy:
        - Top-level keys are merged
        - Later configs override earlier ones
        - Lists are replaced entirely, not merged
        """
        for key, value in source.items():
            target[key] = value

    def _process_default_rules(self, default_rules_setting: Any) -> tuple[bool, list[str] | None]:
        """
        Process default_rules configuration setting.

        Args:
            default_rules_setting: Value of default_rules from config

        Returns:
            Tuple of (enabled, patterns) where:
            - enabled: True if any default rules should be included
            - patterns: None for all, or list of glob patterns to match

        Raises:
            ConfigValidationError: If default_rules setting is invalid
        """
        if default_rules_setting is True:
            return True, None
        elif default_rules_setting is False:
            return False, None
        elif isinstance(default_rules_setting, list):
            patterns = [str(pattern) for pattern in default_rules_setting]
            return True, patterns
        else:
            raise ConfigValidationError(
                f"Invalid default_rules setting: {default_rules_setting}. Must be boolean or list of patterns"
            )

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
            rules_data = raw_config.data.get("rules", {})
            if not isinstance(rules_data, dict):
                raise ConfigValidationError(
                    "Invalid rules section: must be a dictionary",
                    source_path=str(raw_config.source.path),
                )

            for rule_id, rule_config in rules_data.items():
                if not isinstance(rule_config, dict):
                    raise ConfigValidationError(
                        f"Invalid rule config for '{rule_id}': must be a dictionary",
                        rule_id=rule_id,
                        source_path=str(raw_config.source.path),
                    )

                if (
                    raw_config.source.source_type.value == "default"
                    and not self._should_include_default_rule(
                        rule_id, default_rules_enabled, default_rules_patterns
                    )
                ):
                    continue

                if rule_id not in merged_rules:
                    merged_rules[rule_id] = {}

                self._merge_rule_config(
                    merged_rules[rule_id], rule_config, rule_id, raw_config.source.path
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

        Args:
            target: Target rule configuration to merge into
            source: Source rule configuration to merge from
            rule_id: Rule ID for logging
            source_path: Source file path for logging
        """
        for key, value in source.items():
            if key == "type" and key in target and target[key] != value:
                raise ConfigValidationError(
                    f"Cannot change rule type from '{target[key]}' to '{value}'",
                    rule_id=rule_id,
                    source_path=str(source_path),
                )

            target[key] = value
