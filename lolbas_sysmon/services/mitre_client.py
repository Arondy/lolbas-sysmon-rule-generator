"""
Client for fetching and parsing MITRE ATT&CK data.

This module retrieves MITRE ATT&CK Enterprise framework data and
extracts technique ID to name mappings for enriching Sysmon rules
with human-readable technique names.
"""

import json
from pathlib import Path

import httpx

from lolbas_sysmon.config import logger


class MitreClient:
    """
    Client for retrieving MITRE ATT&CK technique names.

    Fetches the MITRE ATT&CK Enterprise framework data and parses it
    to create a mapping of technique IDs (e.g., "T1218.011") to
    human-readable names (e.g., "System Binary Proxy Execution: Rundll32").

    For sub-techniques, the parent technique name is prepended for context.

    Attributes:
        logger: Loguru logger instance bound to this class.
        url: URL of the MITRE ATT&CK STIX bundle.
        default_json: Default path for local JSON cache file.
    """

    def __init__(self, url: str, default_json: str = "enterprise-attack.json") -> None:
        """
        Initialize the MITRE ATT&CK client.

        Args:
            url: URL to fetch MITRE ATT&CK STIX bundle from.
            default_json: Default local file path for caching/loading data.
        """
        self.logger = logger.bind(class_name=self.__class__.__name__)
        self.url = url
        self.default_json = default_json

    def fetch_from_url(self, save_path: str | None = None) -> dict[str, str]:
        """
        Fetch MITRE ATT&CK data from the remote URL.

        Downloads the STIX bundle, optionally saves it locally,
        and parses technique ID to name mappings.

        Args:
            save_path: Optional file path to save the fetched data.

        Returns:
            Dictionary mapping technique IDs to technique names.

        Raises:
            httpx.HTTPError: If the HTTP request fails.
            json.JSONDecodeError: If response is not valid JSON.
        """
        self.logger.info(f"Fetching MITRE ATT&CK data from {self.url}")

        with httpx.Client(timeout=60.0) as client:
            response = client.get(self.url)
            response.raise_for_status()
            bundle = response.json()

        if save_path:
            with open(save_path, "w", encoding="utf-8") as f:
                json.dump(bundle, f, indent=2, ensure_ascii=False)
            self.logger.info(f"Saved MITRE data to {save_path}")

        return self._parse_bundle(bundle)

    def load_from_file(self, file_path: str) -> dict[str, str]:
        """
        Load and parse MITRE ATT&CK data from a local file.

        Args:
            file_path: Path to the JSON file containing STIX bundle.

        Returns:
            Dictionary mapping technique IDs to technique names.

        Raises:
            FileNotFoundError: If the file doesn't exist.
            json.JSONDecodeError: If file content is not valid JSON.
        """
        path = Path(file_path)
        self.logger.info(f"Loading MITRE ATT&CK data from local file: {path}")

        with open(path, "r", encoding="utf-8") as f:
            bundle = json.load(f)

        return self._parse_bundle(bundle)

    def get_technique_names(self, local_path: str | None = None) -> dict[str, str]:
        """
        Get technique name mappings with automatic source selection.

        Implements a fallback chain:
        1. If local_path provided and exists, load from that file
        2. If default JSON file exists, load from it
        3. Otherwise, fetch from URL and cache to default path

        Args:
            local_path: Optional explicit path to local JSON file.

        Returns:
            Dictionary mapping technique IDs to technique names.

        Raises:
            FileNotFoundError: If specified local_path doesn't exist.
            httpx.HTTPError: If fetch fails and no local file available.
            json.JSONDecodeError: If JSON parsing fails.
        """
        if local_path:
            path = Path(local_path)
            if path.exists():
                return self.load_from_file(local_path)
            raise FileNotFoundError(f"MITRE JSON file not found: {local_path}")

        default_path = Path(self.default_json)
        if default_path.exists():
            return self.load_from_file(str(default_path))

        return self.fetch_from_url(save_path=self.default_json)

    def _parse_bundle(self, bundle: dict) -> dict[str, str]:
        """
        Parse STIX bundle to extract technique ID to name mappings.

        Processes attack-pattern objects from the STIX bundle.
        For sub-techniques (IDs containing "."), prepends the parent
        technique name for better context (e.g., "T1218.011" becomes
        "System Binary Proxy Execution: Rundll32").

        Args:
            bundle: Parsed STIX bundle dictionary.

        Returns:
            Dictionary mapping technique IDs (e.g., "T1218", "T1218.011")
            to human-readable technique names.
        """
        objects = bundle.get("objects", [])

        # First pass: collect parent technique names
        parents: dict[str, str] = {}
        for obj in objects:
            if obj.get("type") != "attack-pattern":
                continue
            refs = obj.get("external_references", [])
            if not refs:
                continue
            attack_id = refs[0].get("external_id", "")
            # Parent techniques don't have "." in their ID
            if attack_id and "." not in attack_id:
                parents[attack_id] = obj.get("name", "")

        # Second pass: build full mapping with parent names for sub-techniques
        mapping: dict[str, str] = {}
        for obj in objects:
            if obj.get("type") != "attack-pattern":
                continue
            refs = obj.get("external_references", [])
            if not refs:
                continue

            attack_id = refs[0].get("external_id", "")
            name = obj.get("name", "")

            if not attack_id:
                continue

            # For sub-techniques, prepend parent name
            if "." in attack_id:
                parent_id = attack_id.split(".")[0]
                parent_name = parents.get(parent_id, "Unknown")
                name = f"{parent_name}: {name}"

            mapping[attack_id] = name

        self.logger.info(f"Parsed {len(mapping)} MITRE ATT&CK techniques")
        return mapping
