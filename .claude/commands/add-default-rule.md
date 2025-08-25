---
description: Add a new default rule to Claude Code Guardian
argument-hint: <rule description>
allowed-tools: [Read, Edit, MultiEdit]
---

# Add default rules

Add a new default rule to Claude Code Guardian's built-in rules.

**Instructions:**

1. Read the description provided in `$ARGUMENTS`
2. Read the README to understand supported rule types and configuration format
3. Read the current default.yml to understand the existing structure
4. Create an appropriate rule configuration based on the description
5. Add the new rule to `ccguardian/config/default.yml`
6. Update the README.md table in the "Default Rules" section to include the new rule
7. Update the test file `tests/integration/test_cli_integration.py` to include the new rule in the assertion that checks
for all default rules
8. Run `uv run claude-code-guardian rules` to verify the new rule is properly parsed
9. Format the code using `scripts/format.sh`

**Rule Creation Guidelines:**

- Use appropriate rule type
- Set priority to 30 (same as other default rules)
- Choose appropriate action (`deny`, `warn`, `allow`, etc.)
- Provide clear, helpful message
- Use descriptive rule ID with dot notation (e.g., `security.rule_name`, `performance.rule_name`)
- Group rules by their category (the first segment of the ID)

**Arguments:** $ARGUMENTS
