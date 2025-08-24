"""Pydantic models for configuration validation."""

import re
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator

from ..rules import (
    Action,
    CommandPattern,
    PathAccessRule,
    PathPattern,
    PreUseBashRule,
    Rule,
    Scope,
)


def _validate_regex_pattern(pattern: str) -> None:
    """
    Validate a regex pattern string.

    Args:
        pattern: The regex pattern to validate

    Raises:
        ValueError: If pattern is invalid
    """
    if not pattern or not isinstance(pattern, str):
        raise ValueError("Pattern must be a non-empty string")

    try:
        re.compile(pattern)
    except re.error as e:
        raise ValueError(f"Invalid regex pattern '{pattern}': {e}") from e


def _validate_glob_pattern(pattern: str) -> None:
    """
    Validate a glob pattern string.

    Args:
        pattern: The glob pattern to validate

    Raises:
        ValueError: If pattern is invalid
    """
    if not pattern or not isinstance(pattern, str):
        raise ValueError("Pattern must be a non-empty string")

    try:
        # Use Path.match() which provides better validation than fnmatch
        # Test with a realistic dummy path that should work with valid patterns
        test_path = Path("test/path/file.txt")
        test_path.match(pattern)

        # Additional validation for common glob pattern issues
        # Check for unbalanced brackets which Path.match() might not catch
        bracket_count = 0
        in_bracket = False
        for char in pattern:
            if char == "[":
                if in_bracket:
                    raise ValueError("Nested brackets not allowed in glob patterns")
                in_bracket = True
                bracket_count += 1
            elif char == "]":
                if not in_bracket:
                    raise ValueError("Closing bracket without opening bracket in glob pattern")
                in_bracket = False
                bracket_count -= 1

        # Check for unmatched opening brackets
        if in_bracket or bracket_count != 0:
            raise ValueError("Unmatched brackets in glob pattern")

    except ValueError as e:
        if "bracket" in str(e) or "glob pattern" in str(e):
            raise  # Re-raise our custom bracket errors and glob pattern errors
        raise ValueError(f"Invalid glob pattern '{pattern}': {e}") from e
    except Exception as e:
        # Catch OSError from Path.match() and any other unexpected exceptions
        raise ValueError(f"Invalid glob pattern '{pattern}': {e}") from e


class CommandPatternModel(BaseModel):
    """Pattern definition for bash command rules."""

    pattern: str
    action: Action | None = None
    message: str | None = None

    @field_validator("pattern")
    @classmethod
    def validate_regex_pattern(cls, v: str) -> str:
        """Validate regex pattern using re.compile()."""
        _validate_regex_pattern(v)
        return v


class PathPatternModel(BaseModel):
    """Pattern definition for path access rules."""

    pattern: str
    scope: Scope | None = None
    action: Action | None = None
    message: str | None = None

    @field_validator("pattern")
    @classmethod
    def validate_glob_pattern(cls, v: str) -> str:
        """Validate glob pattern using pathlib.Path.match()."""
        _validate_glob_pattern(v)
        return v


class RuleConfigBase(BaseModel, ABC):
    """Base class for all rule configurations."""

    type: str
    enabled: bool | None = None
    priority: int | None = None
    action: Action | None = None
    message: str | None = None

    @field_validator("priority")
    @classmethod
    def validate_priority(cls, v: int | None) -> int | None:
        """Validate priority is non-negative."""
        if v is not None and v < 0:
            raise ValueError("Priority must be non-negative")
        return v

    def _merge_common_fields(self, partial_config: dict[str, Any]) -> dict[str, Any]:
        """
        Process common fields from partial configuration.

        Args:
            partial_config: Dictionary with partial rule configuration

        Returns:
            Dictionary with validated common fields

        Raises:
            ValueError: If partial_config contains invalid values
        """
        update_fields = {}

        for field in ["enabled", "priority", "action", "message"]:
            if field in partial_config and partial_config[field] is not None:
                value = partial_config[field]

                if field == "action" and isinstance(value, str):
                    try:
                        value = Action(value.lower())
                    except ValueError as e:
                        raise ValueError(f"Invalid action value: {value}") from e

                if field == "priority" and (not isinstance(value, int) or value < 0):
                    raise ValueError(f"Priority must be a non-negative integer, got {value}")

                update_fields[field] = value

        return update_fields

    @abstractmethod
    def merge(self, partial_config: dict[str, Any]) -> "RuleConfigBase":
        """
        Merge partial configuration into this instance.

        Args:
            partial_config: Dictionary with partial rule configuration

        Returns:
            New instance with merged configuration

        Raises:
            ValueError: If partial_config contains invalid values
        """

    @abstractmethod
    def to_rule(self, rule_id: str) -> Rule:
        """
        Convert this rule configuration to a Rule instance.

        Args:
            rule_id: Unique identifier for the rule

        Returns:
            Rule object
        """


class PreUseBashRuleConfig(RuleConfigBase):
    """Configuration for bash command validation rules."""

    type: Literal["pre_use_bash"] = "pre_use_bash"
    pattern: str | None = None
    commands: list[CommandPatternModel] | None = None

    @model_validator(mode="after")
    def validate_pattern_or_commands(self) -> "PreUseBashRuleConfig":
        """Ensure exactly one of pattern or commands is provided."""
        has_pattern = self.pattern is not None
        has_commands = self.commands is not None

        if not has_pattern and not has_commands:
            raise ValueError("PreUseBashRule requires either 'pattern' or 'commands' field")

        if has_pattern and has_commands:
            raise ValueError(
                "Cannot specify both 'pattern' and 'commands' fields - they are mutually exclusive"
            )

        # Convert single pattern to commands list for internal consistency
        if has_pattern and self.pattern:
            _validate_regex_pattern(self.pattern)

            self.commands = [CommandPatternModel(pattern=self.pattern, action=None, message=None)]
            self.pattern = None  # Clear the pattern field

        if self.commands is not None and len(self.commands) == 0:
            raise ValueError("'commands' field cannot be empty")

        return self

    def merge(self, partial_config: dict[str, Any]) -> "PreUseBashRuleConfig":
        """Handle PreUseBashRule-specific merging logic."""
        update_fields = self._merge_common_fields(partial_config)

        # Handle pattern/commands mutual exclusivity
        if "pattern" in partial_config and partial_config["pattern"] is not None:
            # Convert pattern to commands format and replace existing commands
            pattern = partial_config["pattern"]
            _validate_regex_pattern(pattern)
            update_fields["commands"] = [
                CommandPatternModel(pattern=pattern, action=None, message=None)
            ]

        elif "commands" in partial_config and partial_config["commands"] is not None:
            commands_data = partial_config["commands"]
            if not isinstance(commands_data, list) or len(commands_data) == 0:
                raise ValueError("'commands' field must be a non-empty list")

            # Validate and convert to CommandPatternModel instances
            try:
                commands = [
                    CommandPatternModel.model_validate(cmd_data) for cmd_data in commands_data
                ]
            except ValidationError as e:
                raise ValueError(f"Invalid command configuration: {e}") from e

            update_fields["commands"] = commands

        return self.model_copy(update=update_fields)

    def to_rule(self, rule_id: str) -> PreUseBashRule:
        """Convert this rule configuration to a PreUseBashRule instance."""
        commands = []
        for cmd_pattern in self.commands or []:
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
            enabled=self.enabled if self.enabled is not None else True,
            priority=self.priority,
            action=self.action,
            message=self.message,
        )


class PathAccessRuleConfig(RuleConfigBase):
    """Configuration for path access validation rules."""

    type: Literal["path_access"] = "path_access"
    scope: Scope | None = None
    pattern: str | None = None
    paths: list[PathPatternModel] | None = None

    @model_validator(mode="after")
    def validate_pattern_or_paths(self) -> "PathAccessRuleConfig":
        """Ensure exactly one of pattern or paths is provided."""
        has_pattern = self.pattern is not None
        has_paths = self.paths is not None

        if not has_pattern and not has_paths:
            raise ValueError("PathAccessRule requires either 'pattern' or 'paths' field")

        if has_pattern and has_paths:
            raise ValueError(
                "Cannot specify both 'pattern' and 'paths' fields - they are mutually exclusive"
            )

        # Convert single pattern to paths list for internal consistency
        if has_pattern and self.pattern:
            _validate_glob_pattern(self.pattern)

            self.paths = [
                PathPatternModel(pattern=self.pattern, scope=None, action=None, message=None)
            ]
            self.pattern = None  # Clear the pattern field

        if self.paths is not None and len(self.paths) == 0:
            raise ValueError("'paths' field cannot be empty")

        return self

    def merge(self, partial_config: dict[str, Any]) -> "PathAccessRuleConfig":
        """Handle PathAccessRule-specific merging logic."""
        update_fields = self._merge_common_fields(partial_config)

        if "scope" in partial_config and partial_config["scope"] is not None:
            scope = partial_config["scope"]
            if isinstance(scope, str):
                try:
                    scope = Scope(scope.lower())
                except ValueError as e:
                    raise ValueError(f"Invalid scope value: {scope}") from e
            update_fields["scope"] = scope

        # Handle pattern/paths mutual exclusivity
        if "pattern" in partial_config and partial_config["pattern"] is not None:
            # Convert pattern to paths format and replace existing paths
            pattern = partial_config["pattern"]
            _validate_glob_pattern(pattern)
            update_fields["paths"] = [
                PathPatternModel(pattern=pattern, scope=None, action=None, message=None)
            ]

        elif "paths" in partial_config and partial_config["paths"] is not None:
            paths_data = partial_config["paths"]
            if not isinstance(paths_data, list) or len(paths_data) == 0:
                raise ValueError("'paths' field must be a non-empty list")

            # Validate and convert to PathPatternModel instances
            try:
                paths = [PathPatternModel.model_validate(path_data) for path_data in paths_data]
            except ValidationError as e:
                raise ValueError(f"Invalid path configuration: {e}") from e

            update_fields["paths"] = paths

        return self.model_copy(update=update_fields)

    def to_rule(self, rule_id: str) -> PathAccessRule:
        """Convert this rule configuration to a PathAccessRule instance."""
        paths = []
        for path_pattern in self.paths or []:
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
            enabled=self.enabled if self.enabled is not None else True,
            priority=self.priority,
            action=self.action,
            message=self.message,
            scope=self.scope,
        )


# For flexibility in partial configurations, we'll use a custom validator
RuleConfigUnion = PreUseBashRuleConfig | PathAccessRuleConfig | dict[str, Any]

# Mapping from rule types to their corresponding model classes
RULE_TYPE_MODELS = {
    "pre_use_bash": PreUseBashRuleConfig,
    "path_access": PathAccessRuleConfig,
}


class ConfigFile(BaseModel):
    """Top-level configuration file structure."""

    default_rules: bool | list[str] | None = None
    rules: dict[str, RuleConfigUnion] = Field(default_factory=dict)

    @field_validator("rules")
    @classmethod
    def validate_rules(cls, v: dict[str, Any]) -> dict[str, Any]:
        """Validate rule configurations, allowing both complete and partial configs."""
        validated_rules = {}

        for rule_id, rule_config in v.items():
            if not isinstance(rule_id, str) or not rule_id.strip():
                raise ValueError(f"Rule ID '{rule_id}' must be a non-empty string")

            if isinstance(rule_config, dict):
                # Raw dictionary - attempt validation if type is present
                if "type" in rule_config:
                    # Complete rule config - validate with appropriate model
                    rule_type = rule_config["type"]

                    if rule_type in RULE_TYPE_MODELS:
                        model_class = RULE_TYPE_MODELS[rule_type]
                        validated_rules[rule_id] = model_class.model_validate(rule_config)
                    else:
                        valid_types = ", ".join(RULE_TYPE_MODELS.keys())
                        raise ValueError(
                            f"Unknown rule type: {rule_type}. Valid types: {valid_types}"
                        )
                else:
                    # Partial rule config - basic validation only
                    # Validate priority if present
                    if "priority" in rule_config and rule_config["priority"] is not None:
                        priority = rule_config["priority"]
                        if not isinstance(priority, int) or priority < 0:
                            raise ValueError(
                                f"Priority must be a non-negative integer, got {priority}"
                            )

                    # Validate action if present
                    if "action" in rule_config and rule_config["action"] is not None:
                        action = rule_config["action"]
                        if isinstance(action, str):
                            try:
                                Action(action.lower())  # Action values are lowercase
                            except ValueError as e:
                                raise ValueError(f"Invalid action value: {action}") from e

                    # Store as dict for partial configs
                    validated_rules[rule_id] = rule_config
            else:
                # Already validated Pydantic model
                validated_rules[rule_id] = rule_config

        return validated_rules

    @field_validator("default_rules")
    @classmethod
    def validate_default_rules(cls, v: bool | list[str] | None) -> bool | list[str] | None:
        """Validate default_rules field."""
        if v is None or isinstance(v, bool):
            return v

        if isinstance(v, list):
            # Validate all items are strings
            for i, item in enumerate(v):
                if not isinstance(item, str):
                    raise ValueError(f"default_rules list item at index {i} must be a string")
            return v
