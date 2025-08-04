# Claude Code Guardian - System Design

## Overview

Validation and permission system for Claude Code focused on controlling what Claude Code
can execute, read or write. Allowing users to define a set of rules to evaluate.
The system uses Claude Code hooks to enforce the rules.

## Architecture

### Core Components

#### Rule System

Rules are a combination of a trigger condition and action to perform when that condition happens

```python
class Rule(ABC):
    id: str
    type: str
    enabled: bool
    priority: int
    action: str
    message: str
    
    @abstractmethod
    def evaluate(self, context) -> RuleResult

class PreUseBashRule(Rule):
    commands: List[CommandPattern]  # Single pattern config converted to list of one
    
class PathAccessRule(Rule):
    paths: List[PathPattern]  # Single pattern config converted to list of one
    scope: str  # read, write, read_write
```

**Rule Types:**

- **pre_use_bash**: Command validation and optimization for Bash tool
- **path_access**: File system access control for Read/Edit/Write tools

#### Configuration System

Multi-layered configuration hierarchy:

**Configuration Hierarchy:**

1. Default configurations (shipped with package)
2. User-level configuration (`~/.config/claude-code-guardian/` or `$CLAUDE_CODE_GUARDIAN_CONFIG`)
3. Project-level shared configuration (`.claude/guardian/config.yml`)
4. Project-level local configuration (`.claude/guardian/config.local.yml`)

**Project Configuration Pattern:**

- **`config.yml`** (shared): Team-wide rules, committed to version control
- **`config.local.yml`** (local): Personal overrides, added to `.gitignore`
- Local config merges with and overrides shared config settings
- Recommended `.gitignore` entry: `.claude/guardian/config.local.yml`

**Environment Variable Support:**

- **`CLAUDE_CODE_GUARDIAN_CONFIG`**: Override user-level config directory
  - Default: `~/.config/claude-code-guardian/`
  - Custom: `/path/to/custom/config/dir/`

**Configuration Format:**

```yaml
default_rules: true  # true, false, or list of glob patterns like ["security.*"]

rules:
  security.dangerous_command:
    type: pre_use_bash
    pattern: "rm -rf|sudo rm"
    action: deny
    message: "Dangerous command detected"
    priority: 10
    enabled: true
    
  security.git_operations:
    type: pre_use_bash
    action: ask
    priority: 10
    message: "Command requires confirmation"
    commands:
      - pattern: "git push$"
        action: allow
        message: "Standard git push allowed"
      - pattern: "git push origin"
        action: allow 
        message: "Push to origin allowed"
      - pattern: "git push.*--force"
        action: ask
        message: "Force push requires confirmation"
    enabled: true
    
  performance.suggestions:
    type: pre_use_bash
    pattern: "^grep\\b(?!.*\\|)"
    message: "Use ripgrep for better performance"
    action: suggest
    priority: 10
    enabled: true
    
  security.sensitive_file_access:
    type: path_access
    pattern: "**/*.env*"
    scope: read_write
    action: deny
    message: "Access to environment files blocked"
    priority: 10
    enabled: true
    
  security.more_sensitive_files:
    type: path_access
    action: deny
    priority: 10
    paths:
      - pattern: "**/.git/**"
        scope: write
        action: warn
        message: "Direct .git manipulation detected"
      - pattern: "**/config/secrets/**"
        scope: read
        action: deny
        message: "Access to secrets directory blocked"
    enabled: true
```

### Configuration Merging Behavior

#### Rule ID System

- **Rule IDs**: Descriptive names with dot notation (e.g., `security.dangerous_command`, `performance.suggestions`)
- **Uniqueness**: IDs must be unique across all configuration files
- **Merging**: Rules with same ID are merged, with later configs overriding earlier ones

#### Simple Merge Strategy

- Rules with the same ID are merged together
- Any field except `type` can be overridden
- Lists (`paths`, `commands`) are replaced entirely, not merged
- Configuration hierarchy: default → user → shared → local

#### Priority System

1. **Higher priority number = more specific = evaluated first**
2. **Same priority**: Evaluation order is undefined
3. **Rule evaluation**: First matching rule determines the action
4. **Pattern evaluation**: Within a rule's `commands` or `paths` list, patterns are evaluated in the order they appear

#### Configuration Examples

##### Disabling a Rule Locally

```yaml
# .claude/guardian/config.local.yml
rules:
  performance.suggestions:
    enabled: false
```

##### Overriding Rule Action

```yaml
# .claude/guardian/config.local.yml  
rules:
  security.git_operations:
    action: deny  # Change from ask to deny
    message: "Git operations blocked in this project"
```

##### Adding New Rule Locally

```yaml
# .claude/guardian/config.local.yml
rules:
  local.custom_security:
    type: pre_use_bash
    pattern: "curl.*internal"
    action: deny
    message: "Block internal API calls"
    priority: 20
    enabled: true
```

#### Path Access Patterns (Glob)

- **`**/.env*`**: All .env files recursively
- **`**/.git/**`**: Entire .git directory structure  
- **`**/config/secrets/**`**: Any secrets directory under config
- **`/etc/**`**: System configuration (absolute path)
- **`~/.ssh/**`**: SSH keys and config

#### Action Types

- **`allow`**: Permit operation silently
- **`suggest`**: Show alternative but allow operation  
- **`warn`**: Show warning but allow operation
- **`ask`**: Require user confirmation
- **`deny`**: Block operation completely
- **`halt`**: Stop all processing
- **`continue`**: Do nothing, proceed with next rule

#### Scope Types (path_access only)

- **`read`**: Apply to read operations only
- **`write`**: Apply to write operations only
- **`read_write`**: Apply to both read and write operations (default)

## Rule Types and Trigger Conditions

### Supported Rule Types

#### `pre_use_bash` - Bash Command Validation

**Hook Types:** `PreToolUse`
**Tool Names:** `Bash`
**Trigger Condition:** When pattern matches against command
**Context Access:** `tool_input.command`
**Pattern Type:** Regex

```yaml
security.dangerous_command:
  type: pre_use_bash
  pattern: "rm -rf|sudo rm"
  action: deny
  message: "Dangerous command detected"
  priority: 10
  enabled: true

security.git_operations:
  type: pre_use_bash
  action: ask
  priority: 10
  message: "Command requires confirmation"
  commands:
    - pattern: "git push$"
      action: allow
      message: "Standard git push allowed"
    - pattern: "git push origin"
      action: allow 
      message: "Push to origin allowed"
    - pattern: "git push.*--force"
      action: ask
      message: "Force push requires confirmation"
  enabled: true

performance.suggestions:
  type: pre_use_bash
  pattern: "^grep\\b(?!.*\\|)"
  message: "Use ripgrep for better performance"
  action: suggest
  priority: 10
  enabled: true
```

**Fields:**

- `type`: Required, must be `pre_use_bash`
- `pattern` OR `commands`: Required (mutually exclusive in config)
- `pattern`: Single regex pattern (converted to `commands` list of one element internally)
- `commands`: List of command patterns with individual actions and priorities
- `action`: Default action for rule (default: continue)
- `message`: Default message (optional)
- `priority`: Rule priority for evaluation order (optional)
- `enabled`: Whether rule is active (default: true)

#### `path_access` - File System Access Control

**Hook Types:** `PreToolUse`
**Tool Names:** `Read`, `Edit`, `MultiEdit`, `Write`
**Trigger Condition:** When tool accesses matching path
**Context Access:** `tool_input.file_path`
**Pattern Type:** Glob

```yaml
security.sensitive_file_access:
  type: path_access
  pattern: "**/*.env*"
  scope: read_write
  action: deny
  message: "Access to environment files blocked"
  priority: 10
  enabled: true

security.more_sensitive_files:
  type: path_access
  action: deny
  priority: 10
  paths:
    - pattern: "**/.git/**"
      scope: write
      action: warn
      message: "Direct .git manipulation detected"
    - pattern: "**/config/secrets/**"
      scope: read
      action: deny
      message: "Access to secrets directory blocked"
  enabled: true
```

**Fields:**

- `type`: Required, must be `path_access`
- `pattern` OR `paths`: Required (mutually exclusive in config)
- `pattern`: Single glob pattern (converted to `paths` list of one element internally)
- `paths`: List of path patterns with individual scopes, actions, and messages
- `scope`: Access scope - `read`, `write`, or `read_write` (default: `read_write`)
- `action`: Default action for rule (deny)
- `message`: Default message (optional)
- `priority`: Rule priority for evaluation order (optional)
- `enabled`: Whether rule is active (default: true)

## Data Flow

### Validation Process Flow

```text
Claude Code Hook Trigger
├── Context Creation (cchooks)
├── Hook Type Detection (PreToolUse only)
├── Configuration Loading & Merging
├── Rule Set Filtering (by tool name)
├── Rule Evaluation (Priority Order)
├── First Match Wins
├── Action Execution
└── Response Formatting
```

### Rule Evaluation Flow

```text
Rule Evaluation
├── Check if rule enabled
├── Pattern/Command Matching
├── Action Determination
├── Logging
└── Result Generation (first match wins)
```

## References

### Claude Code Hooks Documentation

- **[Claude Code Hooks Guide](https://docs.anthropic.com/en/docs/claude-code/hooks-guide.md)**:
  Comprehensive guide to understanding Claude Code hooks, their lifecycle events,
  and practical implementation examples
- **[Claude Code Hooks Reference](https://docs.anthropic.com/en/docs/claude-code/hooks.md)**:
  Technical reference for hook types, configuration options, and integration patterns

### cchooks Library Documentation

- **[cchooks README](https://github.com/GowayLee/cchooks/blob/main/README.md)**:
  Overview of the cchooks Python library, installation instructions, and basic usage examples
- **[cchooks API Reference](https://github.com/GowayLee/cchooks/blob/main/docs/api-reference.md)**:
  Detailed API documentation for all hook types, context objects, and response methods

These resources are essential for understanding:

- **Hook Types**: PreToolUse, PostToolUse, Notification, Stop, SubagentStop, UserPromptSubmit, PreCompact, SessionStart
- **Hook Lifecycle**: When hooks execute and what context data is available
- **cchooks Integration**: How to use the library for type-safe hook development
- **Response Patterns**: Proper ways to allow, deny, warn, or modify Claude Code behavior

## Command Line Interface

### Diagnostic Commands

#### `claude-code-guardian rules`

Display configuration diagnostics for troubleshooting and transparency:

```bash
$ claude-code-guardian rules

Configuration Sources:
✓ Default: /usr/local/lib/python3.11/site-packages/ccguardian/config/default.yaml
✓ User:    ~/.config/claude-code-guardian/config.yaml
✓ Shared:  .claude/guardian/config.yml
✓ Local:   .claude/guardian/config.local.yml
✗ Environment: CLAUDE_CODE_GUARDIAN_CONFIG (not set)

Merged Configuration:
====================
Default Rules: enabled
Total Rules: 23
Active Rules: 21 (2 disabled)

Rule Evaluation Order (by priority):
=====================
Priority | ID                            | Type         | Command/Path                  | Action
---------|-------------------------------|--------------|-------------------------------|--------
100      | security.git_operations       | pre_use_bash | git push.*--force            | ask
60       | security.git_operations       | pre_use_bash | git push origin              | allow
50       | security.git_operations       | pre_use_bash | git push$                    | allow
20       | local.custom_security         | pre_use_bash | curl.*internal               | deny
10       | security.sensitive_file_access| path_access  | **/*.env*                    | deny
10       | security.more_sensitive_files | path_access  | **/.git/**                   | warn
10       | security.more_sensitive_files | path_access  | **/config/secrets/**         | deny
10       | performance.suggestions       | pre_use_bash | ^grep\\b(?!.*\\|)            | suggest

Disabled Rules:
==============
ID                          | Type
----------------------------|-------------
security.dangerous_command  | pre_use_bash
development.debug_tools     | path_access
```

#### Additional Diagnostic Options

```bash
# Show only enabled rules
claude-code-guardian rules --enabled-only

# Show only specific rule type
claude-code-guardian rules --type pre_use_bash
claude-code-guardian rules --type path_access

# Export merged config to file
claude-code-guardian rules --export merged-config.yaml

# Validate configuration without showing full output
claude-code-guardian rules --validate
```

### Hook Execution Command

#### `claude-code-guardian hook`

Main entry point for Claude Code hook execution

```bash
# This is what Claude Code calls (configured in hooks settings)
claude-code-guardian hook
```

**Functionality:**

- Detects hook type automatically using cchooks `create_context()`
- Loads and merges configuration from all sources
- Evaluates applicable rules
- Returns appropriate response (allow/deny/warn/suggest/ask/halt/continue)
- Logs rule execution for audit and debugging

**Hook Configuration Setup:**

```json
// Claude Code hooks configuration
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "claude-code-guardian hook"
          }
        ]
      }
    ]
  }
}
```
