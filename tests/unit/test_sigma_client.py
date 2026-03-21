"""Unit tests for Sigma client."""

import pytest

from lolbas_sysmon.services import SigmaClient


class TestSigmaClient:
    """Tests for SigmaClient class."""

    @pytest.fixture
    def client(self, tmp_path):
        """Create Sigma client instance with temp cache directory."""
        cache_dir = tmp_path / "sigma_cache"
        return SigmaClient(cache_dir=str(cache_dir))

    def test_get_cache_filename(self, client):
        """Test cache filename generation from URL."""
        url = "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_certutil_download.yml"
        filename = client._get_cache_filename(url)
        # Should contain hash prefix and original filename
        assert filename.endswith("proc_creation_win_certutil_download.yml")
        assert len(filename.split("_")[0]) == 8  # 8-char hash

    def test_get_raw_url_github_blob(self, client):
        """Test converting GitHub blob URL to raw URL."""
        blob_url = "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/test.yml"
        raw_url = client._get_raw_url(blob_url)
        assert raw_url == "https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/test.yml"

    def test_get_raw_url_already_raw(self, client):
        """Test that raw URLs are returned unchanged."""
        raw_url = "https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/test.yml"
        result = client._get_raw_url(raw_url)
        assert result == raw_url

    def test_get_raw_url_invalid(self, client):
        """Test that invalid URLs are returned unchanged."""
        invalid_url = "https://example.com/not-a-github-url.yml"
        result = client._get_raw_url(invalid_url)
        assert result == invalid_url

    def test_is_sigma_url_yml(self, client):
        """Test that .yml URLs are recognized as Sigma URLs."""
        assert client.is_sigma_url("https://example.com/rule.yml") is True
        assert client.is_sigma_url("https://example.com/rule.yaml") is True

    def test_is_sigma_url_github(self, client):
        """Test that GitHub Sigma URLs are recognized."""
        assert client.is_sigma_url("https://github.com/SigmaHQ/sigma/blob/master/rules/test.yml") is True
        assert client.is_sigma_url("https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/test.yml") is True

    def test_is_sigma_url_invalid(self, client):
        """Test that non-Sigma URLs are not recognized."""
        assert client.is_sigma_url("https://example.com/file.txt") is False
        assert client.is_sigma_url("https://example.com/file.json") is False

    def test_get_cached_path_exists(self, client, tmp_path):
        """Test getting path to cached file when it exists."""
        url = "https://example.com/test.yml"
        filename = client._get_cache_filename(url)
        cache_path = client.cache_dir / filename
        cache_path.write_text("test content", encoding="utf-8")

        result = client.get_cached_path(url)
        assert result == cache_path

    def test_get_cached_path_not_exists(self, client):
        """Test getting path returns None when file not cached."""
        url = "https://example.com/nonexistent.yml"
        result = client.get_cached_path(url)
        assert result is None

    def test_clear_cache(self, client, tmp_path):
        """Test clearing cache deletes all .yml files."""
        # Create some test files
        (client.cache_dir / "test1.yml").write_text("test1", encoding="utf-8")
        (client.cache_dir / "test2.yml").write_text("test2", encoding="utf-8")
        (client.cache_dir / "test.txt").write_text("test", encoding="utf-8")

        count = client.clear_cache()
        assert count == 2  # Only .yml files deleted
        assert not (client.cache_dir / "test1.yml").exists()
        assert not (client.cache_dir / "test2.yml").exists()
        assert (client.cache_dir / "test.txt").exists()

    def test_get_cache_stats(self, client):
        """Test getting cache statistics."""
        # Create some test files
        (client.cache_dir / "test1.yml").write_text("test1", encoding="utf-8")
        (client.cache_dir / "test2.yml").write_text("test2", encoding="utf-8")

        stats = client.get_cache_stats()
        assert stats["files"] == 2
        assert stats["size_bytes"] > 0
