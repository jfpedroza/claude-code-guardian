"""Configuration merging logic for hierarchical configuration sources."""

import fnmatch
import logging

from .exceptions import ConfigValidationError
from .models import RuleConfigBase
from .types import Configuration, RawConfiguration

logger = logging.getLogger(__name__)


class ConfigurationMerger:
    """Merges multiple configuration sources into a single configuration."""

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

        rules = [
            rule_config.to_rule(rule_id) for rule_id, rule_config in merged_rules_data.items()
        ]

        # Sort by priority (higher first), then by rule ID for deterministic ordering
        rules.sort(key=lambda r: (-r.priority, r.id))

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
        Merge rules by ID using rule-specific merge methods.

        Args:
            raw_configs: List of raw configurations
            default_rules_setting: Default rules setting (True=all, False=none, list=patterns)

        Returns:
            Dictionary mapping rule ID to validated rule configuration instances

        Raises:
            ConfigValidationError: If first occurrence is incomplete or merge fails
        """
        merged_rules: dict[str, RuleConfigBase] = {}

        for raw_config in raw_configs:
            for rule_id, rule_config in raw_config.data.rules.items():
                if rule_id not in merged_rules:
                    # First occurrence - must be complete RuleConfigBase instance
                    if not isinstance(rule_config, RuleConfigBase):
                        raise ConfigValidationError(
                            f"First occurrence of rule '{rule_id}' must be complete",
                            rule_id=rule_id,
                            source_path=str(raw_config.source.path),
                        )

                    # For default rules, set enabled based on default_rules_setting
                    if raw_config.source.source_type.value == "default":
                        should_enable = self._should_enable_default_rule(
                            rule_id, default_rules_setting
                        )
                        if rule_config.enabled is None:
                            rule_config.enabled = should_enable

                    merged_rules[rule_id] = rule_config
                else:
                    # Subsequent occurrence - can be complete or partial
                    try:
                        if isinstance(rule_config, RuleConfigBase):
                            # Complete replacement - but check type compatibility
                            existing_type = merged_rules[rule_id].type
                            new_type = rule_config.type
                            if existing_type != new_type:
                                raise ConfigValidationError(
                                    f"Cannot change rule type from '{existing_type}' to '{new_type}'",
                                    rule_id=rule_id,
                                    source_path=str(raw_config.source.path),
                                )
                            merged_rules[rule_id] = rule_config
                        else:  # isinstance(rule_config, dict)
                            # Partial merge using rule-specific logic
                            merged_rules[rule_id] = merged_rules[rule_id].merge(rule_config)
                    except ValueError as e:
                        raise ConfigValidationError(
                            f"Failed to merge rule '{rule_id}': {e}",
                            rule_id=rule_id,
                            source_path=str(raw_config.source.path),
                        ) from e

        return merged_rules

    def _should_enable_default_rule(
        self, rule_id: str, default_rules_setting: bool | list[str]
    ) -> bool:
        """
        Check if a default rule should be enabled based on filtering settings.

        Args:
            rule_id: Rule identifier to check
            default_rules_setting: Default rules setting (True=all, False=none, list=patterns)

        Returns:
            True if rule should be enabled
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
