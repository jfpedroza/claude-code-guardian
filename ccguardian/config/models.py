"""Pydantic models for configuration validation."""

import re
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from ..rules import Action, Scope


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


class RuleConfigBase(BaseModel):
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
            # Validate the pattern using the same logic as CommandPatternModel
            _validate_regex_pattern(self.pattern)

            # Convert to commands list
            self.commands = [CommandPatternModel(pattern=self.pattern, action=None, message=None)]
            self.pattern = None  # Clear the pattern field

        # Validate commands list is not empty
        if self.commands is not None and len(self.commands) == 0:
            raise ValueError("'commands' field cannot be empty")

        return self


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
            # Validate the pattern using the same logic as PathPatternModel
            _validate_glob_pattern(self.pattern)

            # Convert to paths list
            self.paths = [
                PathPatternModel(pattern=self.pattern, scope=None, action=None, message=None)
            ]
            self.pattern = None  # Clear the pattern field

        # Validate paths list is not empty
        if self.paths is not None and len(self.paths) == 0:
            raise ValueError("'paths' field cannot be empty")

        return self


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

        raise ValueError("default_rules must be a boolean, list of strings, or None")

    @field_validator("rules")
    @classmethod
    def validate_rules_dict(cls, v: dict[str, Any]) -> dict[str, Any]:
        """Validate rules dictionary has string keys."""
        for key in v.keys():
            if not isinstance(key, str) or not key.strip():
                raise ValueError(f"Rule ID '{key}' must be a non-empty string")
        return v


def validate_rule_config(rule_data: dict[str, Any], rule_id: str) -> RuleConfigBase:
    """
    Validate and convert a rule configuration dictionary to a RuleConfigBase instance.

    Args:
        rule_data: Dictionary containing rule configuration
        rule_id: Rule identifier for error reporting

    Returns:
        Validated RuleConfigBase instance

    Raises:
        ValueError: If rule validation fails
    """
    rule_type = rule_data.get("type")
    if not rule_type:
        raise ValueError(f"Rule '{rule_id}' is missing required 'type' field")

    if rule_type not in RULE_TYPE_MODELS:
        valid_types = ", ".join(RULE_TYPE_MODELS.keys())
        raise ValueError(
            f"Rule '{rule_id}' has unknown type '{rule_type}'. Valid types: {valid_types}"
        )

    model_class = RULE_TYPE_MODELS[rule_type]
    try:
        return model_class.model_validate(rule_data)
    except Exception as e:
        raise ValueError(f"Rule '{rule_id}' validation failed: {e}") from e
