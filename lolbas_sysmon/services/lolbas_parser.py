"""
Parser for raw LOLBAS JSON data.

This module transforms raw JSON dictionaries from the LOLBAS API
into structured LOLBin dataclass objects, with support for filtering
by category.
"""

from lolbas_sysmon.config import logger
from lolbas_sysmon.models import Command, LOLBin


class LOLBASParser:
    """
    Parser for converting raw LOLBAS JSON data to LOLBin objects.

    Handles the transformation of raw JSON entries from the LOLBAS API
    into typed LOLBin dataclass instances, extracting commands,
    categories, and MITRE ATT&CK mappings.

    Attributes:
        logger: Loguru logger instance bound to this class.
    """

    def __init__(self) -> None:
        """Initialize the parser with a bound logger."""
        self.logger = logger.bind(class_name=self.__class__.__name__)

    def parse(self, raw_data: list[dict]) -> list[LOLBin]:
        """
        Parse a list of raw LOLBAS entries into LOLBin objects.

        Iterates through raw JSON dictionaries and converts each to a
        structured LOLBin object. Entries without a valid name are skipped.

        Args:
            raw_data: List of raw dictionaries from LOLBAS JSON API.

        Returns:
            List of parsed LOLBin objects.
        """
        lolbins: list[LOLBin] = []

        for item in raw_data:
            lolbin = self._parse_single(item)
            if lolbin:
                lolbins.append(lolbin)

        self.logger.info(f"Parsed {len(lolbins)} LOLBin objects")
        return lolbins

    def filter_by_category(self, lolbins: list[LOLBin], category: str) -> list[LOLBin]:
        """
        Filter LOLBins to those containing commands in a specific category.

        Args:
            lolbins: List of LOLBin objects to filter.
            category: LOLBAS category name (e.g., "Execute", "Download").

        Returns:
            List of LOLBins that have at least one command in the category.
        """
        filtered = [lb for lb in lolbins if lb.has_category(category)]
        self.logger.debug(f"Filtered {len(filtered)} LOLBins with category '{category}'")
        return filtered

    def _parse_single(self, item: dict) -> LOLBin | None:
        """
        Parse a single raw LOLBAS entry into a LOLBin object.

        Extracts the executable name, original filename, description,
        commands with their categories and MITRE mappings, and
        top-level MITRE ATT&CK technique IDs.

        Args:
            item: Raw dictionary from LOLBAS JSON.

        Returns:
            Parsed LOLBin object, or None if the entry has no name.
        """
        name = item.get("Name", "")
        if not name:
            return None

        commands: list[Command] = []
        for cmd_data in item.get("Commands", []):
            command = Command(
                command=cmd_data.get("Command", ""),
                description=cmd_data.get("Description", ""),
                mitre_id=cmd_data.get("MitreID"),
                category=cmd_data.get("Category", ""),
            )
            commands.append(command)

        mitre_ids: list[str] = []
        for attack in item.get("ATT&CK", []) or []:
            if attack.get("ID"):
                mitre_ids.append(attack.get("ID"))

        return LOLBin(
            name=name, original_filename=item.get("OriginalFileName"), description=item.get("Description", ""), commands=commands, mitre_ids=mitre_ids
        )
