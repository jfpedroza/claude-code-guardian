import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from fnmatch import fnmatch
from pathlib import Path

from cchooks import BaseHookContext, PreToolUseContext

DEFAULT_PRIORITY = 50

type Context = BaseHookContext


class Action(Enum):
    ALLOW = "allow"
    SUGGEST = "suggest"
    WARN = "warn"
    ASK = "ask"
    DENY = "deny"
    HALT = "halt"
    CONTINUE = "continue"


class Scope(Enum):
    READ = "read"
    WRITE = "write"
    READ_WRITE = "read_write"


@dataclass
class RuleResult:
    rule_id: str
    action: Action
    message: str
    matched_pattern: str | None = None


@dataclass
class CommandPattern:
    pattern: str
    action: Action | None = None
    message: str | None = None


@dataclass
class PathPattern:
    pattern: str
    scope: Scope | None = None
    action: Action | None = None
    message: str | None = None


@dataclass
class Rule(ABC):
    id: str
    enabled: bool = True
    priority: int = DEFAULT_PRIORITY
    action: Action = Action.CONTINUE
    message: str | None = None

    @abstractmethod
    def evaluate(self, context: Context) -> RuleResult | None:
        pass


@dataclass
class PreUseBashRule(Rule):
    type: str = "pre_use_bash"
    commands: list[CommandPattern] = field(default_factory=list)
    action: Action = Action.CONTINUE

    def evaluate(self, context: Context) -> RuleResult | None:
        if not self.enabled:
            return None

        if not isinstance(context, PreToolUseContext):
            return None

        if context.tool_name != "Bash":
            return None

        command = context.tool_input.get("command")
        if not command:
            return None

        for pattern in self.commands:
            if re.search(pattern.pattern, command):
                action = pattern.action or self.action
                message = (
                    pattern.message
                    or self.message
                    or f"Command matched pattern: {pattern.pattern}"
                )

                return RuleResult(
                    rule_id=self.id,
                    action=action,
                    message=message,
                    matched_pattern=pattern.pattern,
                )

        return None


@dataclass
class PathAccessRule(Rule):
    type: str = "path_access"
    paths: list[PathPattern] = field(default_factory=list)
    scope: Scope = Scope.READ_WRITE
    action: Action = Action.DENY

    def evaluate(self, context: Context) -> RuleResult | None:
        if not self.enabled:
            return None

        if not isinstance(context, PreToolUseContext):
            return None

        if context.tool_name not in {"Read", "Edit", "MultiEdit", "Write"}:
            return None

        file_path = context.tool_input.get("file_path")
        if not file_path:
            return None

        operation_scope = self._get_operation_scope(context.tool_name)

        for pattern in self.paths:
            if self._path_matches_pattern(file_path, pattern.pattern):
                # Check if the pattern scope applies to this operation
                pattern_scope = pattern.scope or self.scope
                if not self._scope_applies(pattern_scope, operation_scope):
                    continue

                action = pattern.action or self.action
                message = (
                    pattern.message or self.message or f"Path matched pattern: {pattern.pattern}"
                )

                return RuleResult(
                    rule_id=self.id,
                    action=action,
                    message=message,
                    matched_pattern=pattern.pattern,
                )

        return None

    def _get_operation_scope(self, tool_name: str) -> Scope:
        """Determine if the tool operation is read or write."""
        if tool_name == "Read":
            return Scope.READ
        else:  # Edit, MultiEdit, Write
            return Scope.WRITE

    def _path_matches_pattern(self, file_path: str, pattern: str) -> bool:
        """Check if a file path matches a glob pattern."""
        # Convert to Path for consistent handling
        path = Path(file_path)

        # Handle absolute patterns
        if pattern.startswith("/"):
            return fnmatch(str(path), pattern)

        # Handle relative patterns - check against the full path and just the filename/relative parts
        return fnmatch(str(path), pattern) or fnmatch(path.name, pattern)

    def _scope_applies(self, pattern_scope: Scope, operation_scope: Scope) -> bool:
        """Check if a pattern scope applies to the current operation scope."""
        if pattern_scope == Scope.READ_WRITE:
            return True
        return pattern_scope == operation_scope
