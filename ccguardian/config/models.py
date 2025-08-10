"""Pydantic models for configuration validation."""

import re
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from ..rules import Action, Scope


class CommandPatternModel(BaseModel):
    """Pattern definition for bash command rules."""

    pattern: str
    action: Action | None = None
    message: str | None = None

    @field_validator("pattern")
    @classmethod
    def validate_regex_pattern(cls, v: str) -> str:
        """Validate regex pattern using re.compile()."""
        if not v or not isinstance(v, str):
            raise ValueError("Pattern must be a non-empty string")

        try:
            re.compile(v)
        except re.error as e:
            raise ValueError(f"Invalid regex pattern '{v}': {e}") from e

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
        if not v or not isinstance(v, str):
            raise ValueError("Pattern must be a non-empty string")

        try:
            # Use Path.match() which provides better validation than fnmatch
            # Test with a realistic dummy path that should work with valid patterns
            test_path = Path("test/path/file.txt")
            test_path.match(v)

            # Additional validation for common glob pattern issues
            # Check for unbalanced brackets which Path.match() might not catch
            bracket_count = 0
            in_bracket = False
            for char in v:
                if char == "[":
                    if in_bracket:
                        raise ValueError("Nested brackets not allowed in glob patterns")
                    in_bracket = True
                    bracket_count += 1
                elif char == "]":
                    if not in_bracket:
                        raise ValueError(
                            "Closing bracket without opening bracket in glob pattern"
                        )
                    in_bracket = False
                    bracket_count -= 1

            # Check for unmatched opening brackets
            if in_bracket or bracket_count != 0:
                raise ValueError("Unmatched brackets in glob pattern")

        except (ValueError, OSError) as e:
            if isinstance(e, ValueError) and ("bracket" in str(e) or "glob pattern" in str(e)):
                raise  # Re-raise our custom bracket errors and glob pattern errors
            raise ValueError(f"Invalid glob pattern '{v}': {e}") from e
        except Exception as e:
            raise ValueError(f"Invalid glob pattern '{v}': {e}") from e

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
            try:
                re.compile(self.pattern)
            except re.error as e:
                raise ValueError(f"Invalid regex pattern '{self.pattern}': {e}") from e

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
            try:
                test_path = Path("test/path/file.txt")
                test_path.match(self.pattern)
            except (ValueError, OSError) as e:
                raise ValueError(f"Invalid glob pattern '{self.pattern}': {e}") from e

            # Convert to paths list
            self.paths = [
                PathPatternModel(pattern=self.pattern, scope=None, action=None, message=None)
            ]
            self.pattern = None  # Clear the pattern field

        # Validate paths list is not empty
        if self.paths is not None and len(self.paths) == 0:
            raise ValueError("'paths' field cannot be empty")

        return self


# Discriminated union for type-safe rule parsing
RuleConfigUnion = Annotated[
    Union[PreUseBashRuleConfig, PathAccessRuleConfig],
    Field(discriminator="type")
]


class ConfigFile(BaseModel):
    """Top-level configuration file structure."""

    default_rules: bool | list[str] | None = None
    rules: dict[str, RuleConfigUnion] = Field(default_factory=dict)

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
