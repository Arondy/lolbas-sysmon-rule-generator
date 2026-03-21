"""
Sigma rule downloading and caching client.

This module handles fetching Sigma YAML files from URLs (typically GitHub)
and caching them locally for reuse. Supports converting GitHub blob URLs
to raw content URLs.
"""

import hashlib
import re
from pathlib import Path

import httpx

from lolbas_sysmon.config import logger
from lolbas_sysmon.utils import is_cache_stale


class SigmaClient:
    """
    Client for downloading and caching Sigma rules.

    Downloads Sigma YAML files from GitHub or other URLs, caches them
    locally to avoid repeated downloads, and provides access to cached files.

    Attributes:
        logger: Loguru logger instance bound to this class.
        cache_dir: Directory path for caching downloaded rules.
        timeout: HTTP request timeout in seconds.
    """

    def __init__(self, cache_dir: str = "cache_sigma_rules", timeout: float = 30.0) -> None:
        """
        Initialize the Sigma client.

        Args:
            cache_dir: Directory to cache downloaded Sigma rules.
            timeout: HTTP request timeout in seconds.
        """
        self.logger = logger.bind(class_name=self.__class__.__name__)
        self.cache_dir = Path(cache_dir)
        self.timeout = timeout
        self._ensure_cache_dir()

    def _ensure_cache_dir(self) -> None:
        """Create cache directory if it doesn't exist."""
        if not self.cache_dir.exists():
            self.cache_dir.mkdir(parents=True)
            self.logger.info(f"Created Sigma cache directory: {self.cache_dir}")

    def _get_cache_filename(self, url: str) -> str:
        """
        Generate a cache filename from URL.

        Uses URL hash + original filename to avoid collisions while
        keeping filenames readable.

        Args:
            url: Original URL.

        Returns:
            Cache filename.
        """
        url_path = url.split("/")[-1]
        if "?" in url_path:
            url_path = url_path.split("?")[0]

        url_hash = hashlib.md5(url.encode()).hexdigest()[:8]
        return f"{url_hash}_{url_path}"

    def _get_raw_url(self, github_url: str) -> str:
        """
        Convert GitHub blob URL to raw content URL.

        Transforms URLs like:
          https://github.com/SigmaHQ/sigma/blob/master/rules/...
        To:
          https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/...

        Args:
            github_url: GitHub URL (blob or raw).

        Returns:
            Raw content URL.
        """
        if "raw.githubusercontent.com" in github_url:
            return github_url

        pattern = r"https?://github\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.+)"
        match = re.match(pattern, github_url)

        if match:
            owner, repo, branch, path = match.groups()
            return f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}"

        self.logger.warning(f"Could not convert URL to raw format: {github_url}")
        return github_url

    def get_cached_path(self, url: str) -> Path | None:
        """
        Get path to cached file if it exists.

        Args:
            url: Original URL.

        Returns:
            Path to cached file, or None if not cached.
        """
        filename = self._get_cache_filename(url)
        cache_path = self.cache_dir / filename

        if cache_path.exists():
            return cache_path
        return None

    def download_rule(
        self,
        url: str,
        force: bool = False,
        auto_update: bool = False,
        max_age_days: int = 7,
    ) -> tuple[Path | None, bool]:
        """
        Download a Sigma rule from URL.

        Caches the downloaded file for future use. If the file is already
        cached and force=False, returns the cached path without downloading.

        Args:
            url: URL to download from (GitHub blob or raw).
            force: If True, re-download even if cached.
            auto_update: If True, refresh cache if older than max_age_days.
            max_age_days: Maximum age in days before cache is considered stale.

        Returns:
            Tuple of (path, from_cache):
                - path: Path to the downloaded/cached file, or None on error.
                - from_cache: True if returned from cache, False if freshly downloaded.
        """
        if not force:
            cached = self.get_cached_path(url)
            if cached:
                if auto_update and is_cache_stale(cached, max_age_days):
                    self.logger.debug(f"Cached Sigma rule is older than {max_age_days} days, refreshing: {cached.name}")
                else:
                    self.logger.debug(f"Using cached Sigma rule: {cached.name}")
                    return cached, True

        raw_url = self._get_raw_url(url)

        try:
            with httpx.Client(timeout=self.timeout) as client:
                response = client.get(raw_url)
                response.raise_for_status()
                content = response.text
        except httpx.HTTPError as e:
            self.logger.warning(f"Failed to download Sigma rule from {raw_url}: {e}")
            return None, False

        filename = self._get_cache_filename(url)
        cache_path = self.cache_dir / filename

        try:
            cache_path.write_text(content, encoding="utf-8")
            self.logger.debug(f"Downloaded and cached Sigma rule: {filename}")
        except OSError as e:
            self.logger.warning(f"Failed to cache Sigma rule: {e}")
            return None, False

        return cache_path, False

    def download_rules_for_lolbin(
        self,
        detection_urls: list[str],
        force: bool = False,
        force_update: bool = False,
        auto_update: bool = False,
        max_age_days: int = 7,
    ) -> dict[str, Path]:
        """
        Download all Sigma rules for a LOLBin.

        Args:
            detection_urls: List of Sigma rule URLs from LOLBAS Detection section.
            force: If True, re-download even if cached.
            force_update: Alias for force (for backward compatibility).
            auto_update: If True, refresh cache if older than max_age_days.
            max_age_days: Maximum age in days before cache is considered stale.

        Returns:
            Mapping of source URL to downloaded/cached file path.
        """
        url_to_path: dict[str, Path] = {}
        effective_force = force or force_update

        for url in detection_urls:
            if not self.is_sigma_url(url):
                continue

            path, _from_cache = self.download_rule(
                url,
                force=effective_force,
                auto_update=auto_update,
                max_age_days=max_age_days,
            )
            if path:
                url_to_path[url] = path

        return url_to_path

    @staticmethod
    def is_sigma_url(url: str) -> bool:
        """
        Check if URL points to a Sigma rule file.

        Args:
            url: URL to check.

        Returns:
            True if URL appears to point to an actual Sigma YAML file.
        """
        url_lower = url.lower()
        if url_lower.endswith((".yml", ".yaml")):
            return True

        # Accept common GitHub blob/raw Sigma paths that include a YAML filename.
        if ("github.com" in url_lower or "raw.githubusercontent.com" in url_lower) and "/sigma/" in url_lower:
            return ".yml" in url_lower or ".yaml" in url_lower

        return False

    def clear_cache(self) -> int:
        """
        Clear all cached Sigma rules.

        Returns:
            Number of files deleted.
        """
        count = 0
        for file in self.cache_dir.glob("*.yml"):
            try:
                file.unlink()
                count += 1
            except OSError:
                pass

        self.logger.info(f"Cleared {count} cached Sigma rules")
        return count

    def get_cache_stats(self) -> dict[str, int]:
        """
        Get cache statistics.

        Returns:
            Dictionary with 'files' count and 'size_bytes' total.
        """
        files = list(self.cache_dir.glob("*.yml"))
        total_size = sum(f.stat().st_size for f in files)

        return {
            "files": len(files),
            "size_bytes": total_size,
        }
