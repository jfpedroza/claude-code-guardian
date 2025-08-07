"""Configuration validation exceptions."""


class ConfigValidationError(Exception):
    """Raised when configuration validation fails."""

    def __init__(self, message: str, rule_id: str | None = None, source_path: str | None = None):
        """
        Initialize configuration validation error.

        Args:
            message: Error description
            rule_id: Rule ID that caused the error (if applicable)
            source_path: Configuration file path that caused the error (if applicable)
        """
        self.rule_id = rule_id
        self.source_path = source_path

        error_parts = [message]
        if rule_id:
            error_parts.append(f"(rule: {rule_id})")
        if source_path:
            error_parts.append(f"(source: {source_path})")

        super().__init__(" ".join(error_parts))
