"""Core data types for configuration system."""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from ..rules import Rule


class SourceType(Enum):
    """Configuration source types."""

    DEFAULT = "default"
    USER = "user"
    SHARED = "shared"
    LOCAL = "local"


@dataclass
class ConfigurationSource:
    """Represents a configuration source (file location and metadata)."""

    source_type: SourceType
    path: Path
    exists: bool

    @property
    def display_name(self) -> str:
        """Human-friendly name for this source type."""
        return {
            SourceType.DEFAULT: "Default",
            SourceType.USER: "User",
            SourceType.SHARED: "Shared",
            SourceType.LOCAL: "Local",
        }[self.source_type]


@dataclass
class RawConfiguration:
    """Raw configuration data loaded from YAML before processing."""

    source: ConfigurationSource
    data: dict[str, Any]


@dataclass
class Configuration:
    """Final processed configuration with merged rules."""

    sources: list[ConfigurationSource] = field(default_factory=list)
    default_rules_enabled: bool = True
    default_rules_patterns: list[str] | None = None
    rules: list[Rule] = field(default_factory=list)

    @property
    def total_rules(self) -> int:
        """Total number of rules in configuration."""
        return len(self.rules)

    @property
    def active_rules(self) -> int:
        """Number of enabled rules."""
        return sum(1 for rule in self.rules if rule.enabled)

    @property
    def disabled_rules(self) -> int:
        """Number of disabled rules."""
        return self.total_rules - self.active_rules
