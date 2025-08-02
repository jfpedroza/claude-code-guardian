import re
from cchooks import create_context, PreToolUseContext

# Define validation rules as a list of (regex pattern, message) tuples
_VALIDATION_RULES = [
    (
        r"^grep\b(?!.*\|)",
        "Use 'rg' (ripgrep) instead of 'grep' for better performance and features",
    ),
    (
        r"^find\s+\S+\s+-name\b",
        "Use 'rg --files | rg pattern' or 'rg --files -g pattern' instead of 'find -name' for better performance",
    ),
]


def _validate_command(command: str) -> list[str]:
    issues = []
    for pattern, message in _VALIDATION_RULES:
        if re.search(pattern, command):
            issues.append(message)
    return issues


def main():
    c = create_context()

    assert isinstance(c, PreToolUseContext)

    if c.tool_name != "Bash":
        c.output.exit_success()

    command = c.tool_input.get("command", "")

    if not command:
        c.output.exit_success()

    issues = _validate_command(command)
    if issues:
        reason = "\n".join(map(lambda message: f"• {message}", issues))
        c.output.deny(reason)


if __name__ == "__main__":
    main()
