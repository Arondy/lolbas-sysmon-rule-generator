"""Unit tests for configuration loading."""

import tempfile
from pathlib import Path

import pytest

from lolbas_sysmon.config import Config, ConfigLoader
from lolbas_sysmon.config.settings import LolbasConfig, MitreConfig


class TestConfig:
    """Tests for Config dataclass."""

    @pytest.fixture
    def config(self):
        """Create test configuration."""
        return Config(
            categories=["Execute", "Download", "Dump"],
            mappings={
                "Execute": "ProcessCreate",
                "Download": "ProcessCreate",
                "Dump": "ProcessAccess",
            },
            event_conditions={
                "ProcessCreate": ["OriginalFileName", "Image"],
                "ProcessAccess": ["SourceImage", "Image"],
            },
            rule_group_prefix="LOLBAS_",
            rule_group_cmd_prefix="LOLBAS_CMD_",
        )

    def test_get_event_type(self, config):
        """Test getting event type for category."""
        assert config.get_event_type("Execute") == "ProcessCreate"
        assert config.get_event_type("Dump") == "ProcessAccess"

    def test_get_event_type_default(self, config):
        """Test default event type for unknown category."""
        assert config.get_event_type("Unknown") == "ProcessCreate"

    def test_get_rule_group_name_fallback(self, config):
        """Test rule group name for fallback rules."""
        name = config.get_rule_group_name("Execute", with_cmdline=False)
        assert name == "LOLBAS_Execute"

    def test_get_rule_group_name_cmdline(self, config):
        """Test rule group name for CommandLine rules."""
        name = config.get_rule_group_name("Execute", with_cmdline=True)
        assert name == "LOLBAS_CMD_Execute"

    def test_get_rule_group_name_with_spaces(self, config):
        """Test rule group name replaces spaces."""
        name = config.get_rule_group_name("AWL Bypass", with_cmdline=False)
        assert name == "LOLBAS_AWL_Bypass"

    def test_get_condition_tags(self, config):
        """Test getting condition tags for event type."""
        preferred, fallback = config.get_condition_tags("ProcessCreate")
        assert preferred == "OriginalFileName"
        assert fallback == "Image"

    def test_get_condition_tags_single(self, config):
        """Test condition tags when only one tag defined."""
        config.event_conditions["FileCreate"] = ["Image"]
        preferred, fallback = config.get_condition_tags("FileCreate")
        assert preferred == "Image"
        assert fallback is None

    def test_get_condition_tags_default(self, config):
        """Test default condition tags for unknown event type."""
        preferred, fallback = config.get_condition_tags("Unknown")
        assert preferred == "Image"
        assert fallback is None


class TestConfigLoader:
    """Tests for ConfigLoader class."""

    @pytest.fixture
    def loader(self):
        """Create ConfigLoader instance."""
        return ConfigLoader()

    @pytest.fixture
    def sample_toml_content(self):
        """Sample TOML configuration content."""
        return """
[categories]
enabled = ["Execute", "Download"]

[mappings]
"Execute" = "ProcessCreate"
"Download" = "ProcessCreate"

[event_conditions]
ProcessCreate = ["OriginalFileName", "Image"]

[rule_groups]
prefix = "TEST_"
cmd_prefix = "TEST_CMD_"
unique_rules = true

[lolbas]
json_file = "test_lolbas.json"
url = "https://example.com/lolbas.json"

[mitre]
json_file = "test_mitre.json"
url = "https://example.com/mitre.json"
"""

    def test_load_config_from_file(self, loader, sample_toml_content):
        """Test loading configuration from TOML file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write(sample_toml_content)
            temp_path = f.name

        try:
            config = loader.load(temp_path)

            assert config.categories == ["Execute", "Download"]
            assert config.mappings["Execute"] == "ProcessCreate"
            assert config.rule_group_prefix == "TEST_"
            assert config.rule_group_cmd_prefix == "TEST_CMD_"
            assert config.unique_rules is True
            assert config.lolbas.json_file == "test_lolbas.json"
            assert config.mitre.json_file == "test_mitre.json"
        finally:
            Path(temp_path).unlink()

    def test_load_config_file_not_found(self, loader):
        """Test loading non-existent config file."""
        with pytest.raises(FileNotFoundError):
            loader.load("nonexistent_config.toml")

    def test_load_config_defaults(self, loader):
        """Test default values when sections are missing."""
        minimal_toml = """
[categories]
enabled = ["Execute"]
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write(minimal_toml)
            temp_path = f.name

        try:
            config = loader.load(temp_path)

            assert config.categories == ["Execute"]
            assert config.rule_group_prefix == "LOLBAS_"
            assert config.unique_rules is False
            assert isinstance(config.lolbas, LolbasConfig)
            assert isinstance(config.mitre, MitreConfig)
        finally:
            Path(temp_path).unlink()


class TestLolbasConfig:
    """Tests for LolbasConfig dataclass."""

    def test_default_values(self):
        """Test default configuration values."""
        config = LolbasConfig()
        assert config.json_file == "lolbas.json"
        assert "lolbas-project.github.io" in config.url


class TestMitreConfig:
    """Tests for MitreConfig dataclass."""

    def test_default_values(self):
        """Test default configuration values."""
        config = MitreConfig()
        assert config.json_file == "enterprise-attack.json"
        assert "mitre" in config.url
