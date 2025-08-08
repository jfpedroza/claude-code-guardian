"""Rule factory for converting YAML configuration to Python rule objects."""

import logging
import re
from typing import Any

from ..rules import (
    DEFAULT_PRIORITY,
    RULE_TYPES,
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
        Create a Rule object from configuration data.

        Args:
            rule_id: Unique identifier for the rule
            rule_config: Dictionary containing rule configuration

        Returns:
            Rule object

        Raises:
            ConfigValidationError: If rule creation fails
        """
        rule_type = rule_config.get("type")
        if not rule_type:
            raise ConfigValidationError("Rule is missing required 'type' field", rule_id=rule_id)

        if rule_type not in RULE_TYPES:
            valid_types = ", ".join(RULE_TYPES.keys())
            raise ConfigValidationError(
                f"Unknown rule type '{rule_type}'. Valid types: {valid_types}", rule_id=rule_id
            )

        if rule_type == PreUseBashRule.type:
            return self._create_pre_use_bash_rule(rule_id, rule_config)
        elif rule_type == PathAccessRule.type:
            return self._create_path_access_rule(rule_id, rule_config)
        else:
            raise NotImplementedError(
                f"Rule type '{rule_type}' is registered but not implemented in factory"
            )

    def _create_pre_use_bash_rule(self, rule_id: str, config: dict[str, Any]) -> PreUseBashRule:
        """Create a PreUseBashRule from configuration."""
        commands = self._convert_to_command_patterns(config, rule_id)

        enabled = config.get("enabled", True)
        priority = config.get("priority", DEFAULT_PRIORITY)
        action = self._parse_action(config.get("action", "continue"), rule_id)
        message = config.get("message")

        return PreUseBashRule(
            id=rule_id,
            commands=commands,
            enabled=enabled,
            priority=priority,
            action=action,
            message=message,
        )

    def _create_path_access_rule(self, rule_id: str, config: dict[str, Any]) -> PathAccessRule:
        """Create a PathAccessRule from configuration."""
        paths = self._convert_to_path_patterns(config, rule_id)

        enabled = config.get("enabled", True)
        priority = config.get("priority", DEFAULT_PRIORITY)
        action = self._parse_action(config.get("action", "deny"), rule_id)
        message = config.get("message")
        scope = self._parse_scope(config.get("scope", "read_write"), rule_id)

        return PathAccessRule(
            id=rule_id,
            paths=paths,
            enabled=enabled,
            priority=priority,
            action=action,
            message=message,
            scope=scope,
        )

    def _convert_to_command_patterns(
        self, config: dict[str, Any], rule_id: str
    ) -> list[CommandPattern]:
        """
        Convert configuration to list of CommandPattern objects.

        Handles both single pattern and commands list formats:
        - pattern: "regex" -> [CommandPattern(pattern="regex")]
        - commands: [{pattern: "regex", action: "deny"}, ...]
        """
        if "pattern" in config and "commands" in config:
            raise ConfigValidationError(
                "Cannot specify both 'pattern' and 'commands' fields - they are mutually exclusive",
                rule_id=rule_id,
            )

        if "pattern" in config:
            pattern_str = config["pattern"]
            if not self._validate_regex_pattern(pattern_str):
                raise ConfigValidationError(
                    f"Invalid regex pattern: '{pattern_str}'", rule_id=rule_id
                )
            return [CommandPattern(pattern=pattern_str, action=None, message=None)]

        elif "commands" in config:
            commands_list = config["commands"]
            if not isinstance(commands_list, list):
                raise ConfigValidationError("'commands' field must be a list", rule_id=rule_id)

            if not commands_list:
                raise ConfigValidationError("'commands' field cannot be empty", rule_id=rule_id)

            patterns = []
            for i, cmd_config in enumerate(commands_list):
                if not isinstance(cmd_config, dict):
                    raise ConfigValidationError(
                        f"Command configuration at index {i} must be a dictionary",
                        rule_id=rule_id,
                    )

                pattern_str = cmd_config.get("pattern")
                if not pattern_str:
                    raise ConfigValidationError(
                        f"Command pattern at index {i} missing 'pattern' field", rule_id=rule_id
                    )

                if not self._validate_regex_pattern(pattern_str):
                    raise ConfigValidationError(
                        f"Invalid regex pattern at index {i}: '{pattern_str}'", rule_id=rule_id
                    )

                action = (
                    self._parse_action(cmd_config.get("action"), rule_id)
                    if "action" in cmd_config
                    else None
                )
                message = cmd_config.get("message")

                patterns.append(
                    CommandPattern(pattern=pattern_str, action=action, message=message)
                )

            return patterns

        else:
            raise ConfigValidationError(
                "PreUseBashRule requires either 'pattern' or 'commands' field", rule_id=rule_id
            )

    def _convert_to_path_patterns(
        self, config: dict[str, Any], rule_id: str
    ) -> list[PathPattern]:
        """
        Convert configuration to list of PathPattern objects.

        Handles both single pattern and paths list formats:
        - pattern: "*.env" -> [PathPattern(pattern="*.env")]
        - paths: [{pattern: "*.env", scope: "read", action: "deny"}, ...]
        """
        if "pattern" in config and "paths" in config:
            raise ConfigValidationError(
                "Cannot specify both 'pattern' and 'paths' fields - they are mutually exclusive",
                rule_id=rule_id,
            )

        if "pattern" in config:
            pattern_str = config["pattern"]
            if not self._validate_glob_pattern(pattern_str):
                raise ConfigValidationError(
                    f"Invalid glob pattern: '{pattern_str}'", rule_id=rule_id
                )
            return [PathPattern(pattern=pattern_str, scope=None, action=None, message=None)]

        elif "paths" in config:
            paths_list = config["paths"]
            if not isinstance(paths_list, list):
                raise ConfigValidationError("'paths' field must be a list", rule_id=rule_id)

            if not paths_list:
                raise ConfigValidationError("'paths' field cannot be empty", rule_id=rule_id)

            patterns = []
            for i, path_config in enumerate(paths_list):
                if not isinstance(path_config, dict):
                    raise ConfigValidationError(
                        f"Path configuration at index {i} must be a dictionary", rule_id=rule_id
                    )

                pattern_str = path_config.get("pattern")
                if not pattern_str:
                    raise ConfigValidationError(
                        f"Path pattern at index {i} missing 'pattern' field", rule_id=rule_id
                    )

                if not self._validate_glob_pattern(pattern_str):
                    raise ConfigValidationError(
                        f"Invalid glob pattern at index {i}: '{pattern_str}'", rule_id=rule_id
                    )

                scope = (
                    self._parse_scope(path_config.get("scope"), rule_id)
                    if "scope" in path_config
                    else None
                )
                action = (
                    self._parse_action(path_config.get("action"), rule_id)
                    if "action" in path_config
                    else None
                )
                message = path_config.get("message")

                patterns.append(
                    PathPattern(pattern=pattern_str, scope=scope, action=action, message=message)
                )

            return patterns

        else:
            raise ConfigValidationError(
                "PathAccessRule requires either 'pattern' or 'paths' field", rule_id=rule_id
            )

    def _parse_action(self, action_value: Any, rule_id: str) -> Action | None:
        """Parse action string to Action enum."""
        if action_value is None:
            return None

        if isinstance(action_value, Action):
            return action_value

        if isinstance(action_value, str):
            try:
                return Action(action_value.lower())
            except ValueError as e:
                valid_actions = [a.value for a in Action]
                raise ConfigValidationError(
                    f"Invalid action value: '{action_value}'. Valid options: {valid_actions}",
                    rule_id=rule_id,
                ) from e

        raise ConfigValidationError(
            f"Action must be a string, got {type(action_value)}", rule_id=rule_id
        )

    def _parse_scope(self, scope_value: Any, rule_id: str) -> Scope | None:
        """Parse scope string to Scope enum."""
        if scope_value is None:
            return None

        if isinstance(scope_value, Scope):
            return scope_value

        if isinstance(scope_value, str):
            try:
                return Scope(scope_value.lower())
            except ValueError as e:
                valid_scopes = [s.value for s in Scope]
                raise ConfigValidationError(
                    f"Invalid scope value: '{scope_value}'. Valid options: {valid_scopes}",
                    rule_id=rule_id,
                ) from e

        raise ConfigValidationError(
            f"Scope must be a string, got {type(scope_value)}", rule_id=rule_id
        )

    def create_rules_from_merged_data(
        self, merged_rules_data: dict[str, dict[str, Any]]
    ) -> list[Rule]:
        """
        Create a list of Rule objects from merged configuration data.

        Args:
            merged_rules_data: Dictionary mapping rule ID to rule configuration

        Returns:
            List of successfully created Rule objects, sorted by priority (descending)

        Raises:
            ConfigValidationError: If any rule creation fails
        """
        rules = [
            self.create_rule(rule_id, rule_config)
            for rule_id, rule_config in merged_rules_data.items()
        ]

        rules.sort(key=lambda r: (-r.priority, r.id))

        return rules

    def _validate_regex_pattern(self, pattern: str) -> bool:
        """
        Validate that a string is a valid regular expression.

        Args:
            pattern: The regex pattern to validate

        Returns:
            True if pattern is a valid regex, False otherwise
        """
        try:
            re.compile(pattern)
            return True
        except re.error:
            return False

    def _validate_glob_pattern(self, pattern: str) -> bool:
        """
        Validate that a string is a valid glob pattern.

        Args:
            pattern: The glob pattern to validate

        Returns:
            True if pattern is a valid glob pattern, False otherwise
        """
        if not pattern or not isinstance(pattern, str):
            return False

        try:
            # Use Path.match() which provides better validation than fnmatch
            # Test with a realistic dummy path that should work with valid patterns
            from pathlib import Path

            test_path = Path("test/path/file.txt")
            test_path.match(pattern)

            # Additional validation for common glob pattern issues
            # Check for unbalanced brackets which Path.match() might not catch
            bracket_count = 0
            in_bracket = False
            for char in pattern:
                if char == "[":
                    if in_bracket:
                        return False  # Nested brackets not allowed
                    in_bracket = True
                    bracket_count += 1
                elif char == "]":
                    if not in_bracket:
                        return False  # Closing bracket without opening
                    in_bracket = False
                    bracket_count -= 1

            # Check for unmatched opening brackets
            if in_bracket or bracket_count != 0:
                return False

            return True
        except (ValueError, OSError):
            # Path.match() raises ValueError for invalid patterns
            # OSError can occur with some malformed patterns
            return False
        except Exception:
            # Catch any other unexpected issues
            logger.warning(f"Unexpected error validating glob pattern '{pattern}'")
            return False
