"""
Cache utility functions.

This module provides common cache-related utilities used by
LOLBAS, MITRE, and Sigma clients for managing cached data files.
"""

import time
from pathlib import Path


def is_cache_stale(path: Path, max_age_days: int) -> bool:
    """
    Check if a cached file is older than the specified max age.

    Args:
        path: Path to the cached file.
        max_age_days: Maximum age in days before cache is considered stale.

    Returns:
        True if file doesn't exist or is older than max_age_days, False otherwise.
    """
    if not path.exists():
        return True

    if max_age_days <= 0:
        return False

    file_mtime = path.stat().st_mtime
    age_seconds = time.time() - file_mtime
    age_days = age_seconds / (24 * 60 * 60)

    return age_days > max_age_days
