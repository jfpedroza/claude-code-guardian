"""Configuration manager - orchestrates loading, merging, and rule creation."""

import logging

from .loader import ConfigurationLoader
from .merger import ConfigurationMerger
from .types import Configuration

logger = logging.getLogger(__name__)


class ConfigurationManager:
    """Orchestrates configuration loading, merging, and rule creation."""

    def __init__(self):
        """Initialize the configuration manager with loader and merger."""
        self.loader = ConfigurationLoader()
        self.merger = ConfigurationMerger()

    def load_configuration(self) -> Configuration:
        """
        Load complete configuration from all sources.

        Returns:
            Complete merged configuration with Python rule objects
        """
        logger.debug("Starting configuration loading process")

        raw_configs = self.loader.load_all_configurations()
        logger.debug(f"Loaded {len(raw_configs)} configuration files")

        config = self.merger.merge_configurations(raw_configs)
        logger.info(
            f"Configuration loaded: {config.total_rules} total rules, "
            f"{len(config.active_rules)} active, {len(config.disabled_rules)} disabled"
        )

        return config
