"""Unit tests for Sysmon rule generator."""

import pytest

from lolbas_sysmon.config import Config
from lolbas_sysmon.models import Command, LOLBin
from lolbas_sysmon.services import SysmonRuleGenerator


class TestSysmonRuleGenerator:
    """Tests for SysmonRuleGenerator class."""

    @pytest.fixture
    def config(self):
        """Create test configuration."""
        return Config(
            categories=["Execute", "Download"],
            mappings={
                "Execute": ["ProcessCreate"],
                "Download": ["ProcessCreate"],
            },
            event_conditions={
                "ProcessCreate": ["OriginalFileName", "Image"],
            },
            rule_group_prefix="LOLBAS_",
            rule_group_cmd_prefix="LOLBAS_CMD_",
            unique_rules=False,
        )

    @pytest.fixture
    def generator(self, config):
        """Create generator instance."""
        return SysmonRuleGenerator(config)

    @pytest.fixture
    def sample_lolbin(self):
        """Create sample LOLBin for testing."""
        return LOLBin(
            name="certutil.exe",
            original_filename="CertUtil.exe",
            description="Certificate utility",
            commands=[
                Command(command="certutil.exe -urlcache -f http://example.com/file.exe", description="Download file", mitre_id="T1105", category="Download")
            ],
            mitre_ids=["T1105"],
        )

    @pytest.fixture
    def lolbin_without_original(self):
        """Create LOLBin without OriginalFileName."""
        return LOLBin(
            name="evil.exe",
            original_filename=None,
            description="Evil binary",
            commands=[Command(command="evil.exe -run", description="Run evil", mitre_id="T1059", category="Execute")],
            mitre_ids=["T1059"],
        )

    def test_generate_fallback_rule_with_original_filename(self, generator, sample_lolbin):
        """Test fallback rule uses OriginalFileName when available."""
        rule_group = generator.generate_rule_group([sample_lolbin], "Download", with_cmdline=False)

        assert rule_group is not None

        process_create = rule_group.find("ProcessCreate")
        assert process_create is not None
        rule = process_create.find("OriginalFileName")
        assert rule is not None
        assert rule.text == "CertUtil.exe"
        assert rule.get("condition") == "is"

    def test_generate_fallback_rule_without_original_filename(self, generator, lolbin_without_original):
        """Test fallback rule uses Image when no OriginalFileName."""
        rule_group = generator.generate_rule_group([lolbin_without_original], "Execute", with_cmdline=False)

        assert rule_group is not None
        process_create = rule_group.find("ProcessCreate")
        assert process_create is not None
        rule = process_create.find("Image")
        assert rule is not None
        assert rule.text == "\\evil.exe"
        assert rule.get("condition") == "end with"

    def test_generate_cmdline_rule(self, generator, sample_lolbin):
        """Test CommandLine rule generation."""
        rule_group = generator.generate_rule_group([sample_lolbin], "Download", with_cmdline=True)

        assert rule_group is not None
        process_create = rule_group.find("ProcessCreate")
        assert process_create is not None
        rule = process_create.find("Rule")
        assert rule is not None
        assert rule.get("groupRelation") == "and"

        cmdline = rule.find("CommandLine")
        assert cmdline is not None
        assert "-urlcache" in cmdline.text
        assert "-f" in cmdline.text

    def test_generate_cmdline_rule_no_flags(self, generator):
        """Test CommandLine rule not generated when no flags."""
        lolbin = LOLBin(
            name="notepad.exe",
            original_filename="notepad.exe",
            description="Notepad",
            commands=[Command(command="notepad.exe", description="Open notepad", mitre_id=None, category="Execute")],
            mitre_ids=[],
        )
        rule_group = generator.generate_rule_group([lolbin], "Execute", with_cmdline=True)

        assert rule_group is None

    def test_rule_group_name(self, generator, sample_lolbin):
        """Test RuleGroup naming conventions."""
        fallback_group = generator.generate_rule_group([sample_lolbin], "Download", with_cmdline=False)
        cmd_group = generator.generate_rule_group([sample_lolbin], "Download", with_cmdline=True)

        assert fallback_group is not None
        assert cmd_group is not None
        assert fallback_group.get("name") == "LOLBAS_Download"
        assert cmd_group.get("name") == "LOLBAS_CMD_Download"

    def test_rule_group_event_type(self, generator, sample_lolbin):
        """Test RuleGroup uses correct event type."""
        rule_group = generator.generate_rule_group([sample_lolbin], "Download", with_cmdline=False)

        assert rule_group is not None
        process_create = rule_group.find("ProcessCreate")
        assert process_create is not None
        assert process_create.get("onmatch") == "include"

    def test_mitre_attribute(self, generator, sample_lolbin):
        """Test MITRE ATT&CK attribute in rules."""
        technique_names = {"T1105": "Ingress Tool Transfer"}
        generator.mitre_technique_names = technique_names

        rule_group = generator.generate_rule_group([sample_lolbin], "Download", with_cmdline=False)
        assert rule_group is not None
        process_create = rule_group.find("ProcessCreate")
        assert process_create is not None
        rule = process_create.find("OriginalFileName")
        assert rule is not None

        name_attr = rule.get("name")
        assert "technique_id=T1105" in name_attr
        assert "technique_name=Ingress Tool Transfer" in name_attr

    def test_generate_all_rule_groups(self, generator, sample_lolbin):
        """Test generating all rule groups for categories."""
        lolbins_by_category = {"Download": [sample_lolbin]}
        rule_groups = generator.generate_all_rule_groups(lolbins_by_category)

        assert len(rule_groups) == 2
        assert "CMD" in rule_groups[0].get("name")
        assert "CMD" not in rule_groups[1].get("name")

    def test_create_sysmon_config(self, generator, sample_lolbin):
        """Test creating complete Sysmon config."""
        rule_group = generator.generate_rule_group([sample_lolbin], "Download", with_cmdline=False)
        assert rule_group is not None
        sysmon_config = generator.create_sysmon_config([rule_group])

        assert sysmon_config.tag == "Sysmon"
        assert sysmon_config.get("schemaversion") == "4.90"

        event_filtering = sysmon_config.find("EventFiltering")
        assert event_filtering is not None
        assert len(event_filtering) == 1

    def test_to_xml_string(self, generator, sample_lolbin):
        """Test XML string generation."""
        rule_group = generator.generate_rule_group([sample_lolbin], "Download", with_cmdline=False)
        assert rule_group is not None
        sysmon_config = generator.create_sysmon_config([rule_group])

        xml_str = generator.to_xml_string(sysmon_config)

        assert "<Sysmon" in xml_str
        assert "<EventFiltering>" in xml_str
        assert "<RuleGroup" in xml_str

    def test_sanitize_comment_removes_double_dashes(self, generator):
        """Test comment sanitization removes double dashes."""
        text = "This -- is a test -- comment"
        sanitized = generator._sanitize_comment(text)

        assert "--" not in sanitized


class TestUniqueRulesDeduplication:
    """Tests for --unique-rules deduplication logic."""

    @pytest.fixture
    def config_with_unique(self):
        """Create config with unique_rules enabled."""
        return Config(
            categories=["Execute", "Download"],
            mappings={
                "Execute": ["ProcessCreate"],
                "Download": ["ProcessCreate"],
            },
            event_conditions={
                "ProcessCreate": ["OriginalFileName", "Image"],
            },
            rule_group_prefix="LOLBAS_",
            rule_group_cmd_prefix="LOLBAS_CMD_",
            unique_rules=True,
        )

    @pytest.fixture
    def generator_unique(self, config_with_unique):
        """Create generator with unique_rules enabled."""
        return SysmonRuleGenerator(config_with_unique)

    def test_fallback_deduplication(self, generator_unique):
        """Test fallback rules are deduplicated across categories."""
        lolbin = LOLBin(
            name="test.exe",
            original_filename="test.exe",
            description="Test",
            commands=[
                Command(command="test.exe", description="Execute", mitre_id="T1", category="Execute"),
                Command(command="test.exe", description="Download", mitre_id="T2", category="Download"),
            ],
            mitre_ids=[],
        )

        lolbins_by_category = {
            "Execute": [lolbin],
            "Download": [lolbin],
        }

        rule_groups = generator_unique.generate_all_rule_groups(lolbins_by_category)

        fallback_count = 0
        for rg in rule_groups:
            if "CMD" not in rg.get("name", ""):
                for rule in rg.iter("OriginalFileName"):
                    if rule.text == "test.exe":
                        fallback_count += 1

        assert fallback_count == 1

    def test_cmd_rules_with_different_flags_not_deduplicated(self, generator_unique):
        """Test CMD rules with different flags are NOT deduplicated."""
        lolbin = LOLBin(
            name="cmd.exe",
            original_filename="cmd.exe",
            description="Command Prompt",
            commands=[
                Command(command="cmd.exe /c whoami", description="Execute", mitre_id="T1", category="Execute"),
                Command(command="cmd.exe /k dir", description="Download", mitre_id="T2", category="Download"),
            ],
            mitre_ids=[],
        )

        lolbins_by_category = {
            "Execute": [lolbin],
            "Download": [lolbin],
        }

        rule_groups = generator_unique.generate_all_rule_groups(lolbins_by_category)

        cmd_count = 0
        for rg in rule_groups:
            if "CMD" in rg.get("name", ""):
                for _rule in rg.iter("Rule"):
                    cmd_count += 1

        assert cmd_count == 2

    def test_cmd_rules_with_same_flags_deduplicated(self, generator_unique):
        """Test CMD rules with same flags ARE deduplicated."""
        lolbin = LOLBin(
            name="cmd.exe",
            original_filename="cmd.exe",
            description="Command Prompt",
            commands=[
                Command(command="cmd.exe /c whoami", description="Execute", mitre_id="T1", category="Execute"),
                Command(command="cmd.exe /c dir", description="Download", mitre_id="T2", category="Download"),
            ],
            mitre_ids=[],
        )

        lolbins_by_category = {
            "Execute": [lolbin],
            "Download": [lolbin],
        }

        rule_groups = generator_unique.generate_all_rule_groups(lolbins_by_category)

        cmd_count = 0
        for rg in rule_groups:
            if "CMD" in rg.get("name", ""):
                for _rule in rg.iter("Rule"):
                    cmd_count += 1

        assert cmd_count == 1
