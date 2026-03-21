"""Unit tests for MITRE client."""

import json
import tempfile
from pathlib import Path

import pytest

from lolbas_sysmon.services import MitreClient


class TestMitreClient:
    """Tests for MitreClient class."""

    @pytest.fixture
    def client(self):
        """Create MITRE client instance."""
        return MitreClient(url="https://example.com/mitre.json", default_json="test_mitre.json")

    @pytest.fixture
    def sample_bundle(self):
        """Sample MITRE ATT&CK STIX bundle."""
        return {
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
            ]
        }

    def test_load_from_file(self, client, sample_bundle):
        """Test loading MITRE data from local file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump(sample_bundle, f)
            json_path = f.name

        try:
            mapping = client.load_from_file(json_path)
            assert len(mapping) == 4
            assert mapping["T1105"] == "Ingress Tool Transfer"
            assert mapping["T1140"] == "Deobfuscate/Decode Files or Information"
        finally:
            Path(json_path).unlink(missing_ok=True)

    def test_load_from_file_not_found(self, client):
        """Test loading from non-existent file raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            client.load_from_file("nonexistent_file.json")

    def test_parse_bundle(self, client, sample_bundle):
        """Test parsing STIX bundle extracts technique mappings."""
        mapping = client._parse_bundle(sample_bundle)
        assert len(mapping) == 4
        assert mapping["T1105"] == "Ingress Tool Transfer"
        assert mapping["T1140"] == "Deobfuscate/Decode Files or Information"

    def test_parse_bundle_with_subtechniques(self, client, sample_bundle):
        """Test parsing handles sub-techniques with parent name prepended."""
        mapping = client._parse_bundle(sample_bundle)
        # Sub-technique T1218.011 should have parent name prepended
        assert "T1218.011" in mapping
        assert "System Binary Proxy Execution" in mapping["T1218.011"]
        assert "Rundll32" in mapping["T1218.011"]

    def test_parse_bundle_missing_objects(self, client):
        """Test parsing bundle without objects returns empty dict."""
        bundle = {"objects": []}
        mapping = client._parse_bundle(bundle)
        assert mapping == {}

    def test_parse_bundle_missing_external_references(self, client):
        """Test parsing objects without external_references is skipped."""
        bundle = {
            "objects": [
                {
                    "type": "attack-pattern",
                    "name": "Test Technique",
                    "external_references": [],
                }
            ]
        }
        mapping = client._parse_bundle(bundle)
        assert mapping == {}

    def test_get_technique_names_with_local_path(self, client, sample_bundle):
        """Test getting technique names with explicit local path."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump(sample_bundle, f)
            json_path = f.name

        try:
            mapping = client.get_technique_names(local_path=json_path)
            assert len(mapping) == 4
            assert mapping["T1105"] == "Ingress Tool Transfer"
        finally:
            Path(json_path).unlink(missing_ok=True)

    def test_get_technique_names_file_not_found(self, client):
        """Test getting technique names with non-existent file raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            client.get_technique_names(local_path="nonexistent_file.json")
