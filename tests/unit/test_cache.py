"""Unit tests for cache utility functions."""

import time

from lolbas_sysmon.utils import is_cache_stale


class TestIsCacheStale:
    """Tests for is_cache_stale function."""

    def test_file_not_exists(self, tmp_path):
        """Test returns True when file doesn't exist."""
        nonexistent_path = tmp_path / "nonexistent.txt"
        assert is_cache_stale(nonexistent_path, max_age_days=7) is True

    def test_fresh_file(self, tmp_path):
        """Test returns False for freshly created file."""
        fresh_file = tmp_path / "fresh.txt"
        fresh_file.write_text("test", encoding="utf-8")
        assert is_cache_stale(fresh_file, max_age_days=7) is False

    def test_old_file(self, tmp_path):
        """Test returns True for file older than max_age_days."""
        old_file = tmp_path / "old.txt"
        old_file.write_text("test", encoding="utf-8")
        # Set modification time to 10 days ago
        old_time = time.time() - (10 * 24 * 60 * 60)
        import os

        os.utime(old_file, (old_time, old_time))
        assert is_cache_stale(old_file, max_age_days=7) is True

    def test_max_age_zero(self, tmp_path):
        """Test returns False when max_age_days is 0."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("test", encoding="utf-8")
        assert is_cache_stale(test_file, max_age_days=0) is False

    def test_max_age_negative(self, tmp_path):
        """Test returns False when max_age_days is negative."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("test", encoding="utf-8")
        assert is_cache_stale(test_file, max_age_days=-1) is False
