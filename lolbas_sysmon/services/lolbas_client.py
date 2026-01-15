"""
HTTP client for fetching LOLBAS data.

This module provides functionality to fetch LOLBin data from the
LOLBAS project API or load it from a local JSON file. Supports
automatic caching of fetched data for offline use.
"""

import json
from pathlib import Path

import httpx

from lolbas_sysmon.config import logger


class LOLBASClient:
    """
    Client for retrieving LOLBAS (Living Off The Land Binaries and Scripts) data.

    Fetches LOLBin definitions from the LOLBAS project API or loads them
    from local JSON files. Supports automatic fallback to cached data
    and saving fetched data for future use.

    Attributes:
        logger: Loguru logger instance bound to this class.
        url: URL of the LOLBAS JSON API endpoint.
        default_json: Default path for local JSON file.
    """

    def __init__(self, url: str, default_json: str = "lolbas.json") -> None:
        """
        Initialize the LOLBAS client.

        Args:
            url: URL to fetch LOLBAS data from.
            default_json: Default local file path for caching/loading data.
        """
        self.logger = logger.bind(class_name=self.__class__.__name__)
        self.url = url
        self.default_json = default_json

    def fetch_lolbas_data(self, save_path: str | None = None) -> list[dict]:
        """
        Fetch LOLBAS data from the remote API.

        Makes an HTTP GET request to the configured URL and returns
        the parsed JSON data. Optionally saves the response to a file.

        Args:
            save_path: Optional file path to save the fetched data.

        Returns:
            List of raw LOLBin entry dictionaries.

        Raises:
            httpx.HTTPError: If the HTTP request fails.
            json.JSONDecodeError: If response is not valid JSON.
        """
        self.logger.info(f"Fetching LOLBAS data from {self.url}")

        with httpx.Client(timeout=30.0) as client:
            response = client.get(self.url)
            response.raise_for_status()
            data = response.json()

        self.logger.info(f"Fetched {len(data)} LOLBin entries")

        if save_path:
            with open(save_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            self.logger.info(f"Saved LOLBAS data to {save_path}")

        return data

    def load_from_file(self, file_path: str) -> list[dict]:
        """
        Load LOLBAS data from a local JSON file.

        Args:
            file_path: Path to the JSON file containing LOLBAS data.

        Returns:
            List of raw LOLBin entry dictionaries.

        Raises:
            FileNotFoundError: If the file doesn't exist.
            json.JSONDecodeError: If file content is not valid JSON.
        """
        path = Path(file_path)
        self.logger.info(f"Loading LOLBAS data from local file: {path}")

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        self.logger.info(f"Loaded {len(data)} LOLBin entries from {path}")
        return data

    def get_lolbas_data(self, local_path: str | None = None) -> list[dict]:
        """
        Get LOLBAS data with automatic source selection.

        Implements a fallback chain:
        1. If local_path provided, load from that file
        2. If default JSON file exists, load from it
        3. Otherwise, fetch from URL and cache to default path

        Args:
            local_path: Optional explicit path to local JSON file.

        Returns:
            List of raw LOLBin entry dictionaries.

        Raises:
            FileNotFoundError: If specified local_path doesn't exist.
            httpx.HTTPError: If fetch fails and no local file available.
            json.JSONDecodeError: If JSON parsing fails.
        """
        if local_path:
            return self.load_from_file(local_path)

        default_path = Path(self.default_json)
        if default_path.exists():
            return self.load_from_file(str(default_path))

        return self.fetch_lolbas_data(save_path=self.default_json)
