"""
Sysmon rule generation from LOLBAS data.

This module generates Sysmon XML detection rules based on LOLBin definitions.
It creates two types of rules for each category:
- CommandLine rules: More specific, match executable + command-line flags
- Fallback rules: Match only executable name/OriginalFileName

When unique_rules mode is enabled, duplicate rules are skipped:
- CMD rules: deduplicated by (executable, event_type, flags)
- Fallback rules: deduplicated by (executable, event_type)

Note: CommandLine rules are only generated for event types that support
the CommandLine field (ProcessCreate). Other event types like FileCreate,
ProcessAccess, NetworkConnect, and ImageLoad do not have CommandLine
and only get fallback rules.

ImageLoad rules are only generated for LOLBins with .dll extension.
"""

from lxml import etree

from lolbas_sysmon.config import Config, logger
from lolbas_sysmon.models import LOLBin, MitreInfo

# Event types that support CommandLine field
CMDLINE_SUPPORTED_EVENTS = {"ProcessCreate"}

# Event types that require DLL-only LOLBins
DLL_ONLY_EVENTS = {"ImageLoad"}


class SysmonRuleGenerator:
    """
    Generator for Sysmon detection rules based on LOLBAS data.

    Creates XML RuleGroup elements with detection rules for LOLBins.
    Supports both CommandLine-based rules (more specific) and fallback
    rules (executable name only). Includes MITRE ATT&CK technique
    annotations in rule attributes.

    Supports multiple event types per category (ProcessCreate, NetworkConnect,
    ImageLoad, etc.). ImageLoad rules are only generated for DLL-based LOLBins.

    When unique_rules is enabled, tracks generated rules to skip duplicates
    across different categories within the same event type.

    Attributes:
        logger: Loguru logger instance bound to this class.
        config: Configuration object with mappings and prefixes.
        mitre_technique_names: Mapping of technique IDs to names.
        _generated_cmd_rules: Tracker for CMD rules (executable, event_type, flags_key).
        _generated_fallback_rules: Tracker for fallback rules (executable, event_type).
    """

    def __init__(
        self,
        config: Config | None = None,
        mitre_technique_names: dict[str, str] | None = None,
    ) -> None:
        """
        Initialize the rule generator.

        Args:
            config: Configuration with category mappings and rule prefixes.
                   Defaults to empty Config if not provided.
            mitre_technique_names: Optional mapping of MITRE technique IDs
                                   to human-readable names.
        """
        self.logger = logger.bind(class_name=self.__class__.__name__)
        self.config = config or Config()
        self.mitre_technique_names = mitre_technique_names or {}
        # Trackers for deduplication (used when unique_rules=True)
        # CMD rules: set of (executable_key, event_type, flags_key)
        self._generated_cmd_rules: set[tuple[str, str, str]] = set()
        # Fallback rules: set of (executable_key, event_type)
        self._generated_fallback_rules: set[tuple[str, str]] = set()

    def _reset_trackers(self) -> None:
        """Reset deduplication trackers. Called at start of generate_all_rule_groups."""
        self._generated_cmd_rules.clear()
        self._generated_fallback_rules.clear()

    def _is_dll(self, lolbin: LOLBin) -> bool:
        """
        Check if LOLBin is a DLL file.

        Args:
            lolbin: LOLBin object.

        Returns:
            True if the LOLBin name ends with .dll (case-insensitive).
        """
        return lolbin.name.lower().endswith(".dll")

    def _get_executable_key(self, lolbin: LOLBin, event_type: str) -> str:
        """
        Get a normalized key for the executable.

        Args:
            lolbin: LOLBin object.
            event_type: Sysmon event type for determining condition tags.

        Returns:
            Normalized lowercase key like "originalfilename:cmd.exe" or "image:\\cmd.exe"
        """
        preferred_tag, fallback_tag = self.config.get_condition_tags(event_type)

        if preferred_tag == "OriginalFileName" and lolbin.original_filename:
            return f"originalfilename:{lolbin.original_filename.lower()}"
        elif preferred_tag == "ImageLoaded":
            return f"imageloaded:\\{lolbin.name.lower()}"
        else:
            tag_name = fallback_tag if preferred_tag == "OriginalFileName" else preferred_tag
            if tag_name is None:
                tag_name = "Image"
            return f"{tag_name.lower()}:\\{lolbin.name.lower()}"

    def _get_flags_key(self, flags: list[str]) -> str:
        """
        Get a normalized key for command-line flags.

        Args:
            flags: List of flags.

        Returns:
            Sorted, semicolon-joined lowercase string of flags.
        """
        return ";".join(sorted(f.lower() for f in flags))

    def _is_cmd_rule_duplicate(self, executable_key: str, event_type: str, flags_key: str) -> bool:
        """
        Check if a CMD rule with same executable, event_type and flags already exists.

        Args:
            executable_key: Normalized executable identifier.
            event_type: Sysmon event type (e.g., "ProcessCreate").
            flags_key: Normalized flags string.

        Returns:
            True if duplicate, False otherwise.
        """
        return (executable_key, event_type, flags_key) in self._generated_cmd_rules

    def _is_fallback_rule_duplicate(self, executable_key: str, event_type: str) -> bool:
        """
        Check if a fallback rule with same executable and event_type already exists.

        Args:
            executable_key: Normalized executable identifier.
            event_type: Sysmon event type.

        Returns:
            True if duplicate, False otherwise.
        """
        return (executable_key, event_type) in self._generated_fallback_rules

    def _mark_cmd_rule_generated(self, executable_key: str, event_type: str, flags_key: str) -> None:
        """Record that a CMD rule has been generated."""
        self._generated_cmd_rules.add((executable_key, event_type, flags_key))

    def _mark_fallback_rule_generated(self, executable_key: str, event_type: str) -> None:
        """Record that a fallback rule has been generated."""
        self._generated_fallback_rules.add((executable_key, event_type))

    def _supports_commandline(self, event_type: str) -> bool:
        """
        Check if event type supports CommandLine conditions.

        Only ProcessCreate (Event ID 1) supports CommandLine in Sysmon.
        FileCreate, ProcessAccess, NetworkConnect, ImageLoad do not.

        Args:
            event_type: Sysmon event type name.

        Returns:
            True if CommandLine rules can be generated for this event type.
        """
        return event_type in CMDLINE_SUPPORTED_EVENTS

    def _requires_dll_only(self, event_type: str) -> bool:
        """
        Check if event type only applies to DLL LOLBins.

        ImageLoad events should only be generated for .dll files.

        Args:
            event_type: Sysmon event type name.

        Returns:
            True if only DLL LOLBins should be used.
        """
        return event_type in DLL_ONLY_EVENTS

    def _filter_lolbins_for_event_type(self, lolbins: list[LOLBin], event_type: str) -> list[LOLBin]:
        """
        Filter LOLBins applicable for a specific event type.

        For ImageLoad, only return DLL-based LOLBins.
        For other event types, return all LOLBins.

        Args:
            lolbins: List of LOLBin objects.
            event_type: Sysmon event type.

        Returns:
            Filtered list of LOLBins.
        """
        if self._requires_dll_only(event_type):
            return [lb for lb in lolbins if self._is_dll(lb)]
        return lolbins

    def generate_rule_group(
        self,
        lolbins: list[LOLBin],
        category: str,
        with_cmdline: bool = False,
    ) -> etree._Element | None:
        """
        Generate a RuleGroup element for a specific category.

        Creates either CommandLine-based rules (more specific matching)
        or fallback rules (executable name only) based on with_cmdline flag.
        Supports multiple event types per category, creating separate event
        sections within the same RuleGroup.

        When unique_rules is enabled, skips rules that were already generated
        for the same executable within the same event type.

        Args:
            lolbins: List of LOLBin objects to generate rules for.
            category: LOLBAS category (e.g., "Execute", "Download").
            with_cmdline: If True, generate CommandLine rules; otherwise fallback.

        Returns:
            RuleGroup XML element, or None if no rules were generated.
        """
        group_name = self.config.get_rule_group_name(category, with_cmdline)
        event_types = self.config.get_event_types(category)
        unique_rules = self.config.unique_rules

        rule_group = etree.Element("RuleGroup", name=group_name, groupRelation="or")
        total_rules_added = 0

        for event_type in event_types:
            if with_cmdline and not self._supports_commandline(event_type):
                self.logger.debug(f"Skipping CMD rules for category '{category}' event '{event_type}': does not support CommandLine")
                continue

            # Filter LOLBins for this event type (e.g., DLLs only for ImageLoad)
            filtered_lolbins = self._filter_lolbins_for_event_type(lolbins, event_type)
            if not filtered_lolbins:
                continue

            event_element = etree.SubElement(rule_group, event_type, onmatch="include")
            rules_added = 0
            rules_skipped = 0

            for lolbin in filtered_lolbins:
                executable_key = self._get_executable_key(lolbin, event_type)
                rule_element = None

                if with_cmdline:
                    flags = lolbin.get_command_flags_for_category(category)
                    if not flags:
                        continue

                    flags_key = self._get_flags_key(flags)

                    if unique_rules and self._is_cmd_rule_duplicate(executable_key, event_type, flags_key):
                        self.logger.debug(f"Skipping duplicate CMD rule: {lolbin.name} (event_type={event_type}, flags={flags_key})")
                        rules_skipped += 1
                        continue

                    rule_element = self._generate_cmdline_rule(lolbin, category, event_type)
                    if rule_element is not None and unique_rules:
                        self._mark_cmd_rule_generated(executable_key, event_type, flags_key)
                else:
                    if unique_rules and self._is_fallback_rule_duplicate(executable_key, event_type):
                        self.logger.debug(f"Skipping duplicate fallback rule: {lolbin.name} (event_type={event_type})")
                        rules_skipped += 1
                        continue

                    rule_element = self._generate_fallback_rule(lolbin, category, event_type)
                    if rule_element is not None and unique_rules:
                        self._mark_fallback_rule_generated(executable_key, event_type)

                if rule_element is not None:
                    description = lolbin.get_description_for_category(category)
                    if description:
                        comment = etree.Comment(f" {self._sanitize_comment(description)} ")
                        event_element.append(comment)
                    event_element.append(rule_element)
                    rules_added += 1

            # Remove empty event element
            if rules_added == 0:
                rule_group.remove(event_element)
            else:
                total_rules_added += rules_added
                rule_type = "CommandLine" if with_cmdline else "fallback"
                log_msg = f"Generated {event_type} section for '{group_name}' with {rules_added} {rule_type} rules"
                if rules_skipped > 0:
                    log_msg += f" ({rules_skipped} duplicates skipped)"
                self.logger.debug(log_msg)

        if total_rules_added == 0:
            return None

        return rule_group

    def generate_all_rule_groups(
        self,
        lolbins_by_category: dict[str, list[LOLBin]],
        rule_type: str = "both",
    ) -> list[etree._Element]:
        """
        Generate all rule groups for multiple categories.

        Creates CommandLine rules first (more specific, higher priority),
        then fallback rules for each category.

        When unique_rules is enabled, resets trackers at the start and
        skips duplicate rules across categories.

        Args:
            lolbins_by_category: Dictionary mapping category names to LOLBin lists.
            rule_type: Type of rules to generate: "cmd", "fallback", or "both".

        Returns:
            List of RuleGroup XML elements (CMD groups first, then fallback).
        """
        self._reset_trackers()

        rule_groups: list[etree._Element] = []

        # Generate CommandLine rules first (more specific)
        if rule_type in ("cmd", "both"):
            for category, lolbins in lolbins_by_category.items():
                if lolbins:
                    cmd_group = self.generate_rule_group(lolbins, category, with_cmdline=True)
                    if cmd_group is not None:
                        rule_groups.append(cmd_group)

        # Generate fallback rules second
        if rule_type in ("fallback", "both"):
            for category, lolbins in lolbins_by_category.items():
                if lolbins:
                    fallback_group = self.generate_rule_group(lolbins, category, with_cmdline=False)
                    if fallback_group is not None:
                        rule_groups.append(fallback_group)

        return rule_groups

    def create_sysmon_config(self, rule_groups: list[etree._Element] | etree._Element) -> etree._Element:
        """
        Create a complete Sysmon config element with rule groups.

        Args:
            rule_groups: Single RuleGroup or list of RuleGroup elements.

        Returns:
            Root Sysmon XML element with EventFiltering section.
        """
        sysmon = etree.Element("Sysmon", schemaversion="4.90")
        event_filtering = etree.SubElement(sysmon, "EventFiltering")

        if isinstance(rule_groups, list):
            for rg in rule_groups:
                event_filtering.append(rg)
        else:
            event_filtering.append(rule_groups)

        return sysmon

    def _generate_fallback_rule(self, lolbin: LOLBin, category: str, event_type: str) -> etree._Element | None:
        """
        Generate a fallback rule matching only executable name.

        Uses OriginalFileName if available (more reliable), otherwise
        falls back to Image path matching. For ImageLoad events, uses
        ImageLoaded tag.

        Args:
            lolbin: LOLBin object to generate rule for.
            category: LOLBAS category for MITRE mapping.
            event_type: Sysmon event type for determining condition tags.

        Returns:
            XML element for the detection rule.
        """
        preferred_tag, fallback_tag = self.config.get_condition_tags(event_type)

        if preferred_tag == "OriginalFileName" and lolbin.original_filename:
            rule = etree.Element("OriginalFileName", condition="is")
            rule.text = lolbin.original_filename
        elif preferred_tag == "ImageLoaded":
            rule = etree.Element("ImageLoaded", condition="end with")
            rule.text = f"\\{lolbin.name}"
        elif preferred_tag in ("SourceImage", "Image") or fallback_tag:
            tag_name = fallback_tag if preferred_tag == "OriginalFileName" else preferred_tag
            if tag_name is None:
                tag_name = "Image"
            rule = etree.Element(tag_name, condition="end with")
            rule.text = f"\\{lolbin.name}"
        else:
            rule = etree.Element(preferred_tag, condition="end with")
            rule.text = f"\\{lolbin.name}"

        mitre_infos = lolbin.get_mitre_info_for_category(category, self.mitre_technique_names)
        if mitre_infos:
            rule.set("name", self._create_mitre_attribute(mitre_infos))

        return rule

    def _generate_cmdline_rule(self, lolbin: LOLBin, category: str, event_type: str) -> etree._Element | None:
        """
        Generate a CommandLine rule with executable + flag matching.

        Creates a compound rule (groupRelation="and") that matches both
        the executable and specific command-line flags extracted from
        LOLBAS command examples.

        Args:
            lolbin: LOLBin object to generate rule for.
            category: LOLBAS category for flag extraction and MITRE mapping.
            event_type: Sysmon event type for determining condition tags.

        Returns:
            Rule XML element, or None if no flags found for category.
        """
        flags = lolbin.get_command_flags_for_category(category)
        if not flags:
            return None

        preferred_tag, fallback_tag = self.config.get_condition_tags(event_type)

        rule = etree.Element("Rule", groupRelation="and")

        mitre_infos = lolbin.get_mitre_info_for_category(category, self.mitre_technique_names)
        if mitre_infos:
            rule.set("name", self._create_mitre_attribute(mitre_infos))

        if preferred_tag == "OriginalFileName" and lolbin.original_filename:
            image_elem = etree.SubElement(rule, "OriginalFileName", condition="is")
            image_elem.text = lolbin.original_filename
        elif preferred_tag in ("SourceImage", "Image") or fallback_tag:
            tag_name = fallback_tag if preferred_tag == "OriginalFileName" else preferred_tag
            if tag_name is None:
                tag_name = "Image"
            image_elem = etree.SubElement(rule, tag_name, condition="end with")
            image_elem.text = f"\\{lolbin.name}"
        else:
            image_elem = etree.SubElement(rule, preferred_tag, condition="end with")
            image_elem.text = f"\\{lolbin.name}"

        cmdline_elem = etree.SubElement(rule, "CommandLine", condition="contains any")
        cmdline_elem.text = ";".join(flags)

        return rule

    def _sanitize_comment(self, text: str) -> str:
        """
        Sanitize text for use in XML comments.

        Removes double-dashes (--) which are invalid in XML comments,
        and handles trailing dashes.

        Args:
            text: Raw text to sanitize.

        Returns:
            Sanitized text safe for XML comments.
        """
        sanitized = text.strip()
        while "--" in sanitized:
            sanitized = sanitized.replace("--", "—")
        if sanitized.endswith("-"):
            sanitized = sanitized[:-1] + "—"
        return sanitized

    def _create_mitre_attribute(self, mitre_infos: list[MitreInfo]) -> str:
        """
        Create MITRE ATT&CK annotation attribute value.

        Formats technique information as semicolon-separated key=value pairs
        for inclusion in rule 'name' attribute.

        Args:
            mitre_infos: List of MitreInfo objects with technique data.

        Returns:
            Formatted string for 'name' attribute.
        """
        parts: list[str] = []
        for info in mitre_infos:
            parts.append(f"technique_id={info.technique_id},technique_name={info.technique_name}")
        return ";".join(parts)

    def to_xml_string(self, element: etree._Element, pretty: bool = True) -> str:
        """
        Convert XML element to string representation.

        Args:
            element: XML element to serialize.
            pretty: If True, format with indentation.

        Returns:
            XML string without declaration.
        """
        return etree.tostring(element, pretty_print=pretty, encoding="unicode", xml_declaration=False)

    def save_to_file(self, element: etree._Element, path: str) -> None:
        """
        Save XML element to file with declaration.

        Args:
            element: XML element to save.
            path: Output file path.

        Raises:
            OSError: If file writing fails.
        """
        xml_bytes = etree.tostring(element, pretty_print=True, encoding="utf-8", xml_declaration=True)

        with open(path, "wb") as f:
            f.write(xml_bytes)

        self.logger.info(f"Saved rules to {path}")
