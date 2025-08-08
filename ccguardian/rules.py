import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from fnmatch import fnmatch
from pathlib import Path

from cchooks import HookContext, PostToolUseContext, PreToolUseContext

DEFAULT_PRIORITY = 50


class Action(Enum):
    ALLOW = "allow"
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


class Rule(ABC):
    hook_map: dict[str, set[str]]
    type: str

    def __init__(
        self,
        id: str,
        enabled: bool,
        priority: int,
        action: Action,
        message: str | None,
    ):
        self.id = id
        self.enabled = enabled
        self.priority = priority
        self.action = action
        self.message = message

    @abstractmethod
    def evaluate(self, context: HookContext) -> RuleResult | None:
        pass

    def pre_evaluate(self, context: HookContext) -> bool:
        if not self.enabled:
            return False

        hook_map = self.__class__.hook_map

        if context.hook_event_name not in hook_map:
            return False

        match context:
            case PreToolUseContext() | PostToolUseContext():
                return context.tool_name in hook_map[context.hook_event_name]

        return False


class PreUseBashRule(Rule):
    type = "pre_use_bash"
    hook_map = {"PreToolUse": {"Bash"}}
    default_action = Action.CONTINUE

    def __init__(
        self,
        id: str,
        commands: list[CommandPattern] | None = None,
        enabled: bool = True,
        priority: int = DEFAULT_PRIORITY,
        action: Action | None = None,
        message: str | None = None,
    ):
        super().__init__(id, enabled, priority, action or self.default_action, message)
        self.commands = commands or []

    def evaluate(self, context: HookContext) -> RuleResult | None:
        if not self.pre_evaluate(context):
            return None

        assert isinstance(context, PreToolUseContext)

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


class PathAccessRule(Rule):
    type = "path_access"
    hook_map = {"PreToolUse": {"Read", "Edit", "MultiEdit", "Write"}}
    default_action = Action.DENY
    default_scope = Scope.READ_WRITE

    def __init__(
        self,
        id: str,
        paths: list[PathPattern] | None = None,
        scope: Scope | None = None,
        enabled: bool = True,
        priority: int | None = None,
        action: Action | None = None,
        message: str | None = None,
    ):
        super().__init__(
            id, enabled, priority or DEFAULT_PRIORITY, action or self.default_action, message
        )
        self.paths = paths or []
        self.scope = scope or self.default_scope

    def evaluate(self, context: HookContext) -> RuleResult | None:
        if not self.pre_evaluate(context):
            return None

        assert isinstance(context, PreToolUseContext)

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
        if tool_name == "Read":
            return Scope.READ
        else:  # Edit, MultiEdit, Write
            return Scope.WRITE

    def _path_matches_pattern(self, file_path: str, pattern: str) -> bool:
        path = Path(file_path)

        # Handle absolute patterns
        if pattern.startswith("/"):
            return fnmatch(str(path), pattern)

        # Handle relative patterns - check against the full path and just the filename/relative parts
        return fnmatch(str(path), pattern) or fnmatch(path.name, pattern)

    def _scope_applies(self, pattern_scope: Scope, operation_scope: Scope) -> bool:
        if pattern_scope == Scope.READ_WRITE:
            return True
        return pattern_scope == operation_scope


RULE_TYPES: dict[str, type[Rule]] = {
    "pre_use_bash": PreUseBashRule,
    "path_access": PathAccessRule,
}
