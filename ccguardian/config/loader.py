"""Configuration loading from multiple sources."""

import logging
import os
from pathlib import Path

import yaml

from .types import ConfigurationSource, RawConfiguration, SourceType

logger = logging.getLogger(__name__)


class ConfigurationLoader:
    """Loads configuration from multiple hierarchical sources."""

    def find_default_config(self) -> ConfigurationSource:
        """Find the default configuration shipped with the package."""
        config_dir = Path(__file__).parent
        default_path = config_dir / "default.yml"

        return ConfigurationSource(
            source_type=SourceType.DEFAULT, path=default_path, exists=default_path.exists()
        )

    def find_user_config(self) -> ConfigurationSource:
        """Find user-level configuration, checking environment variable override."""
        env_config_dir = os.getenv("CLAUDE_CODE_GUARDIAN_CONFIG")

        if env_config_dir:
            config_path = Path(env_config_dir) / "config.yml"
        else:
            home = Path.home()
            config_path = home / ".config" / "claude-code-guardian" / "config.yml"

        return ConfigurationSource(
            source_type=SourceType.USER, path=config_path, exists=config_path.exists()
        )

    def find_project_configs(self) -> tuple[ConfigurationSource, ConfigurationSource]:
        """Find project-level configurations using CLAUDE_PROJECT_DIR or current directory."""
        # Use CLAUDE_PROJECT_DIR if set (when running from Claude Code hook)
        # Otherwise default to current working directory for testing
        project_dir_env = os.getenv("CLAUDE_PROJECT_DIR")
        if project_dir_env:
            project_root = Path(project_dir_env)
        else:
            project_root = Path.cwd()

        guardian_dir = project_root / ".claude" / "guardian"
        shared_path = guardian_dir / "config.yml"
        local_path = guardian_dir / "config.local.yml"

        shared_source = ConfigurationSource(
            source_type=SourceType.SHARED, path=shared_path, exists=shared_path.exists()
        )

        local_source = ConfigurationSource(
            source_type=SourceType.LOCAL, path=local_path, exists=local_path.exists()
        )

        return shared_source, local_source

    def discover_all_sources(self) -> list[ConfigurationSource]:
        """Discover all configuration sources in hierarchical order."""

        default = self.find_default_config()
        user = self.find_user_config()
        shared, local = self.find_project_configs()

        return [default, user, shared, local]

    def load_yaml_file(self, source: ConfigurationSource) -> RawConfiguration | None:
        """Load and parse a YAML configuration file safely."""
        if not source.exists:
            logger.debug(f"Configuration file does not exist: {source.path}")
            return None

        try:
            with open(source.path, encoding="utf-8") as f:
                data = yaml.safe_load(f)

            if data is None:
                logger.warning(f"Configuration file is empty: {source.path}")
                return None

            if not isinstance(data, dict):
                logger.error(f"Configuration file must contain a YAML object: {source.path}")
                return None

            logger.debug(f"Successfully loaded configuration from: {source.path}")
            return RawConfiguration(source=source, data=data)

        except yaml.YAMLError as e:
            logger.error(f"Failed to parse YAML configuration {source.path}: {e}")
            return None
        except FileNotFoundError:
            logger.debug(f"Configuration file not found: {source.path}")
            return None
        except PermissionError:
            logger.error(f"Permission denied reading configuration: {source.path}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error loading configuration {source.path}: {e}")
            return None

    def load_all_configurations(self) -> list[RawConfiguration]:
        """Load all available configurations in hierarchical order."""
        sources = self.discover_all_sources()
        configurations = []

        for source in sources:
            config = self.load_yaml_file(source)
            if config is not None:
                configurations.append(config)

        return configurations
