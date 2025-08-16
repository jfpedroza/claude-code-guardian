# Claude Code Guardian

Validation and permission system for Claude Code focused on controlling what Claude Code
can execute, read or write. Allowing users to define a set of rules to evaluate.
The system uses Claude Code hooks to enforce the rules.

## Features

- **Security Controls**: Block dangerous commands and restrict file access
- **Performance Optimization**: Suggest better alternatives to common tools
- **Policy Enforcement**: Implement organization-wide development policies
- **Hierarchical Configuration**: Multi-layered configuration with team and personal overrides

## Quick Setup

### 1. Install Claude Code Guardian

Install directly from GitHub using `uvx`:

```bash
uvx --from git+https://github.com/jfpedroza/claude-code-guardian claude-code-guardian --help
```

### 2. Configure Claude Code Hooks

Add the following to your Claude Code settings (`.claude/settings.json` or `~/.claude/settings.json`):

```json
{
  "hooks": {
    "SessionStart": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "uvx --from git+https://github.com/jfpedroza/claude-code-guardian claude-code-guardian hook"
          }
        ]
      }
    ],
    "PreToolUse": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "uvx --from git+https://github.com/jfpedroza/claude-code-guardian claude-code-guardian hook"
          }
        ]
      }
    ]
  }
}
```

### 3. Test Installation

```bash
# Should show help and available commands
uvx --from git+https://github.com/jfpedroza/claude-code-guardian claude-code-guardian

# View current configuration and rules
uvx --from git+https://github.com/jfpedroza/claude-code-guardian claude-code-guardian rules
```

## Configuration

### Configuration Hierarchy

The system loads configuration from multiple sources in this order (later sources override earlier ones):

1. **Default Rules**: Built-in rules shipped with the package
2. **User Config**: `~/.config/claude-code-guardian/config.yml` (or custom via `$CLAUDE_CODE_GUARDIAN_CONFIG/config.yml`)
3. **Project Shared**: `.claude/guardian/config.yml` (committed to version control)
4. **Project Local**: `.claude/guardian/config.local.yml` (personal overrides, should be in `.gitignore`)

### Configuration Format

```yaml
# Enable or disable built-in default rules
default_rules: true  # or false, or list of glob patterns like ["security.*"]

rules:
  security.dangerous_commands:
    type: pre_use_bash
    pattern: "rm -rf|sudo rm"
    action: deny
    message: "Dangerous command detected"
    priority: 100
    enabled: true

  security.git_operations:
    type: pre_use_bash
    action: ask
    priority: 90
    message: "Git command requires confirmation"
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

  performance.grep_alternative:
    type: pre_use_bash
    pattern: "^grep\\b(?!.*\\|)"
    action: deny
    message: "Use 'rg' (ripgrep) for better performance"
    priority: 50
    enabled: true

  security.env_files:
    type: path_access
    pattern: "**/*.env*"
    scope: read_write
    action: deny
    message: "Access to environment files blocked"
    priority: 80
    enabled: true

  security.sensitive_paths:
    type: path_access
    action: warn  # default action
    priority: 70
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

- **Rule IDs**: Descriptive names with dot notation (e.g., `security.dangerous_command`, `performance.suggestions`),
but any name works
- **Merging**: Rules with same ID are merged, with later configs overriding earlier ones

#### Merge Strategy

- Rules with the same ID are merged together
- Any field except `type` can be overridden
- Lists (`paths`, `commands`) are replaced entirely, not merged
- Configuration hierarchy: default → user → shared → local

#### Priority System

1. **Higher priority number = more specific = evaluated first**
2. **Same priority**: Evaluation order is undefined
3. **Rule evaluation**: First matching rule determines the action
4. **Pattern evaluation**: Within a rule's `commands` or `paths` list, patterns are evaluated in the order they appear

## Default Rules

Claude Code Guardian comes with built-in default rules that provide basic security and performance optimizations.
All default rules have a priority of 30. Only security rules are enabled by default.

You can enable all default rules by setting `default_rules: true` in your configuration,
disable them with `default_rules: false` or enable specific categories using patterns like `default_rules: ["performance.*"]`.

| Rule ID | Type | Description |
|---------|------|-------------|
| `security.git_access` | `path_access` | Blocks direct write access to `.git` directories |
| `security.git_commands` | `pre_use_bash` | Prevents `git push --force`, suggests `--force-with-lease` instead |
| `performance.grep_suggestion` | `pre_use_bash` | Suggests using `rg` (ripgrep) instead of `grep` |
| `performance.find_suggestion` | `pre_use_bash` | Suggests using ripgrep file search instead of `find -name` commands |

**View Complete Default Rules:** [ccguardian/config/default.yml](https://github.com/jfpedroza/claude-code-guardian/blob/main/ccguardian/config/default.yml)

**Note**: Current default rules are mostly there to test the system. Suggestions are welcome on what should be included
by default.

## Rule Types

### `pre_use_bash` - Bash Command Validation

Validates commands before the Bash tool executes them.

**Hook Types:** `PreToolUse`
**Tool Names:** `Bash`
**Trigger Condition:** When pattern matches against command
**Context Access:** `tool_input.command`
**Pattern Type:** Regex

**Single Pattern Format:**

```yaml
rule_name:
  type: pre_use_bash
  pattern: "regex_pattern"
  action: deny|allow|ask|warn|halt|continue
  message: "Custom message"
  priority: 100
  enabled: true
```

**Multiple Commands Format:**

```yaml
rule_name:
  type: pre_use_bash
  action: ask  # default action
  message: "Default message"
  priority: 100
  commands:
    - pattern: "specific_pattern"
      action: allow
      message: "Override message"
    - pattern: "another_pattern"
      action: deny
  enabled: true
```

**Fields:**

- **`type`**: Required, must be `pre_use_bash`
- **`pattern` OR `commands`**: Required (mutually exclusive in config)
  - **`pattern`**: Single regex pattern (converted to `commands` list of one element internally)
  - **`commands`**: List of command patterns with individual actions and priorities
- **`action`**: Default action for rule (default: `continue`)
- **`message`**: Default message (optional)
- **`priority`**: Rule priority for evaluation order (default: 50)
- **`enabled`**: Whether rule is active (default: `true`)

### `path_access` - File System Access Control

Controls access to files and directories for Read, Edit, MultiEdit, and Write tools.

**Hook Types:** `PreToolUse`
**Tool Names:** `Read`, `Edit`, `MultiEdit`, `Write`
**Trigger Condition:** When tool accesses matching path
**Context Access:** `tool_input.file_path`
**Pattern Type:** Glob

**Single Pattern Format:**

```yaml
rule_name:
  type: path_access
  pattern: "glob_pattern"
  scope: read|write|read_write
  action: deny|allow|ask|warn|halt|continue
  message: "Custom message"
  priority: 100
  enabled: true
```

**Multiple Paths Format:**

```yaml
rule_name:
  type: path_access
  action: deny  # default action
  priority: 100
  paths:
    - pattern: "**/.git/**"
      scope: write
      action: warn
      message: "Git directory write access"
    - pattern: "**/secrets/**"
      scope: read_write
      action: deny
      message: "Secrets access blocked"
  enabled: true
```

**Fields:**

- **`type`**: Required, must be `path_access`
- **`pattern` OR `paths`**: Required (mutually exclusive in config)
  - **`pattern`**: Single glob pattern (converted to `paths` list of one element internally)
  - **`paths`**: List of path patterns with individual scopes, actions, and messages
- **`scope`**: Access scope - `read`, `write`, or `read_write` (default: `read_write`)
- **`action`**: Default action for rule (default: `deny`)
- **`message`**: Default message (optional)
- **`priority`**: Rule priority for evaluation order (default: 50)
- **`enabled`**: Whether rule is active (default: `true`)

## Actions

- **`allow`**: Permit operation silently
- **`warn`**: Show warning, continue with Claude's default permission system
- **`ask`**: Require user confirmation
- **`deny`**: Block operation completely
- **`halt`**: Stop all processing
- **`continue`**: Do nothing, let Claude's default permission system run

## Scopes (path_access only)

- **`read`**: Apply to read operations only (Read tool)
- **`write`**: Apply to write operations only (Edit, MultiEdit, Write tools)
- **`read_write`**: Apply to both read and write operations (default)

## CLI Commands

### `claude-code-guardian`

Main entry point. Shows help when run without arguments.

```bash
# Show help
claude-code-guardian
claude-code-guardian -h
claude-code-guardian --help
```

### `claude-code-guardian hook`

Hook execution entry point called by Claude Code.

```bash
# Standard execution (used by Claude Code hooks)
claude-code-guardian hook

# Verbose logging for debugging
claude-code-guardian hook --verbose
claude-code-guardian hook -v
```

### `claude-code-guardian rules`

Display configuration diagnostics and rule information.

```bash
# Show complete configuration and rules
claude-code-guardian rules

# Verbose output with debug information
claude-code-guardian rules --verbose
claude-code-guardian rules -v
```

**Sample Output:**

```text
Configuration Sources:
✓ Default: /usr/local/lib/python3.12/site-packages/ccguardian/config/default.yml
✓ User:    ~/.config/claude-code-guardian/config.yml
✗ Shared:  .claude/guardian/config.yml
✓ Local:   .claude/guardian/config.local.yml
✗ Environment: CLAUDE_CODE_GUARDIAN_CONFIG (not set)

Merged Configuration:
====================
Default Rules: enabled
Total Rules: 15
Active Rules: 13 (2 disabled)

Rule Evaluation Order (by priority):
=====================

ID: security.dangerous_commands | Type: pre_use_bash | Priority: 100
Commands:
- `rm -rf|sudo rm` (action: deny)

ID: security.git_operations | Type: pre_use_bash | Priority: 90
Commands:
- `git push.*--force` (action: ask)
- `git push origin` (action: allow)
- `git push$` (action: allow)

ID: security.env_files | Type: path_access | Priority: 80
Paths:
- `**/*.env*` [read_write] (action: deny)

Disabled Rules:
==============
ID: performance.grep_alternative | Type: pre_use_bash
ID: security.temp_files | Type: path_access
```

## Environment Variables

- **`CLAUDE_CODE_GUARDIAN_CONFIG`**: Override user-level config directory
  - Default: `~/.config/claude-code-guardian/`
  - Example: `export CLAUDE_CODE_GUARDIAN_CONFIG="/custom/config/path"`

- **`CLAUDE_PROJECT_DIR`**: Project directory (automatically set by Claude Code)
  - Used to locate `.claude/guardian/` configuration files

## Development

### Requirements

- Python 3.12+
- Dependencies: `cchooks`, `click`, `PyYAML`

### Building from Source

```bash
# Clone the repository
git clone https://github.com/jfpedroza/claude-code-guardian.git
cd claude-code-guardian

# Install dependencies
uv sync

# Test installation
uv run claude-code-guardian --help
uv run claude-code-guardian rules

# Run tests
uv run pytest
```

## Debugging & Troubleshooting

### Log Files

Claude Code Guardian logs all activity to a rotating log file located at:

- **Linux/macOS**: `~/.local/share/claude-code-guardian/guardian.log`
- **Windows**: `%LOCALAPPDATA%/claude-code-guardian/guardian.log`

Log files are automatically rotated when they reach 10MB, keeping the last 5 files.

### Enable Debug Logging

Use the `--verbose` flag to enable debug-level logging:

```bash
# Enable verbose logging for hook execution
claude-code-guardian hook --verbose

# Enable verbose logging for rules command
claude-code-guardian rules --verbose
```

### Check Configuration

View your complete configuration and rule evaluation order:

```bash
claude-code-guardian rules
```

### Verify Hook Setup

Ensure your Claude Code `settings.json` includes the hook configuration for both
`SessionStart` and `PreToolUse` events.

### Common Issues

1. **"Command not found"**: Ensure `uvx` installation was successful
2. **"No rules active"**: Check configuration files exist and contain valid YAML
3. **"Permission denied"**: Verify file permissions on configuration directories
4. **"Hook not executing"**: Confirm Claude Code hooks are properly configured

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
