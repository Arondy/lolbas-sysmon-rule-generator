"""
Sysmon configuration management and rule merging.

This module handles loading, parsing, and modifying existing Sysmon XML
configuration files. It supports intelligent merging of new LOLBAS rules
with existing configs, detecting duplicates and optionally replacing them.
"""

from pathlib import Path

from lxml import etree

from lolbas_sysmon.config import logger

# Tags that identify executable names in Sysmon rules
EXECUTABLE_TAGS = {"OriginalFileName", "Image", "SourceImage", "TargetImage", "ParentImage", "ImageLoaded"}


class SysmonConfigManager:
    """
    Manager for Sysmon XML configuration files.

    Handles loading existing Sysmon configs, finding specific elements,
    and merging new LOLBAS-generated rules while detecting duplicates.
    Supports both CommandLine rules and simple executable-matching rules.

    Attributes:
        logger: Loguru logger instance bound to this class.
        config_path: Path to the Sysmon config file.
        tree: Parsed XML tree (set after load()).
        root: Root XML element (set after load()).
    """

    def __init__(self, config_path: str) -> None:
        """
        Initialize config manager with file path.

        Args:
            config_path: Path to Sysmon XML configuration file.
        """
        self.logger = logger.bind(class_name=self.__class__.__name__)
        self.config_path = Path(config_path)
        self.tree: etree._ElementTree | None = None
        self.root: etree._Element | None = None

    def load(self) -> None:
        """
        Load and parse the Sysmon configuration file.

        Raises:
            FileNotFoundError: If config file doesn't exist.
            etree.XMLSyntaxError: If XML is malformed.
        """
        parser = etree.XMLParser(remove_blank_text=False, remove_comments=False)
        self.tree = etree.parse(str(self.config_path), parser)
        self.root = self.tree.getroot()
        self.logger.info(f"Loaded Sysmon config from {self.config_path}")

    def find_event_filtering(self) -> etree._Element | None:
        """
        Find the EventFiltering section in the config.

        Returns:
            EventFiltering element, or None if not found.
        """
        if self.root is None:
            return None
        event_filtering = self.root.find(".//EventFiltering")
        if event_filtering is None:
            event_filtering = self.root.find("EventFiltering")
        return event_filtering

    def find_rule_group(self, group_name: str) -> etree._Element | None:
        """
        Find a RuleGroup by its name attribute.

        Args:
            group_name: Value of the 'name' attribute to search for.

        Returns:
            RuleGroup element, or None if not found.
        """
        if self.root is None:
            return None
        for rg in self.root.iter("RuleGroup"):
            if rg.get("name") == group_name:
                return rg
        return None

    def find_event_section_in_group(self, rule_group: etree._Element, event_type: str) -> etree._Element | None:
        """
        Find an event type section within a RuleGroup.

        Args:
            rule_group: RuleGroup element to search in.
            event_type: Event type name (e.g., "ProcessCreate").

        Returns:
            Event section element, or None if not found.
        """
        return rule_group.find(event_type)

    def get_all_existing_executables(self) -> set[str]:
        """
        Get all executable names from existing fallback rules.

        Scans all executable-related tags (OriginalFileName, Image, etc.)
        that are NOT inside compound Rule elements, returning lowercase names.

        Returns:
            Set of lowercase executable names.
        """
        executables: set[str] = set()
        if self.root is None:
            return executables

        for tag in EXECUTABLE_TAGS:
            for elem in self.root.iter(tag):
                parent = elem.getparent()
                if parent is not None and parent.tag == "Rule":
                    continue
                if elem.text:
                    name = elem.text.split("\\")[-1].lower()
                    executables.add(name)

        return executables

    def get_all_executables_for_coverage(self) -> set[str]:
        """
        Get ALL executable names from the config for coverage analysis.

        Unlike get_all_existing_executables, this method includes executables
        inside compound Rule elements. Use this when you need an exhaustive
        inventory of executables present in the config.

        Returns:
            Set of lowercase executable names.
        """
        executables: set[str] = set()
        if self.root is None:
            return executables

        for tag in EXECUTABLE_TAGS:
            for elem in self.root.iter(tag):
                if elem.text:
                    name = elem.text.split("\\")[-1].lower()
                    executables.add(name)

        return executables

    def get_all_existing_cmdline_rules(self) -> dict[str, list[set[str]]]:
        """
        Get all existing CommandLine rules with their flags.

        Scans compound Rule elements (groupRelation="and") and extracts
        executable names paired with their CommandLine flag sets.

        Returns:
            Dict mapping lowercase executable names to lists of flag sets.
        """
        cmdline_rules: dict[str, list[set[str]]] = {}
        if self.root is None:
            return cmdline_rules

        for rule in self.root.iter("Rule"):
            if rule.get("groupRelation") != "and":
                continue

            exec_name: str | None = None
            flags: set[str] = set()

            for child in rule:
                if child.tag in EXECUTABLE_TAGS and child.text:
                    exec_name = child.text.split("\\")[-1].lower()
                elif child.tag == "CommandLine" and child.text:
                    flags = set(f.lower().strip() for f in child.text.split(";"))

            if exec_name and flags:
                if exec_name not in cmdline_rules:
                    cmdline_rules[exec_name] = []
                cmdline_rules[exec_name].append(flags)

        return cmdline_rules

    def insert_rule_group(self, rule_group: etree._Element) -> None:
        """
        Insert a new RuleGroup into the EventFiltering section.

        Args:
            rule_group: RuleGroup element to insert.

        Raises:
            ValueError: If EventFiltering section not found.
        """
        event_filtering = self.find_event_filtering()
        if event_filtering is None:
            raise ValueError("EventFiltering section not found in Sysmon config")

        event_filtering.append(rule_group)
        self.logger.info(f"Inserted new RuleGroup '{rule_group.get('name')}'")

    def merge_rule_groups(self, new_rule_groups: list[etree._Element], force: bool = False) -> tuple[int, int]:
        """
        Merge multiple rule groups into the existing config.

        Args:
            new_rule_groups: List of RuleGroup elements to merge.
            force: If True, replace existing duplicate rules.

        Returns:
            Tuple of (added_count, skipped_count).
        """
        total_added = 0
        total_skipped = 0

        for rule_group in new_rule_groups:
            added, skipped = self.merge_rules(rule_group, force=force)
            total_added += added
            total_skipped += skipped

        return (total_added, total_skipped)

    def merge_rules(self, new_rule_group: etree._Element, force: bool = False) -> tuple[int, int]:
        """
        Merge a single rule group into the existing config.

        Handles three scenarios:
        1. RuleGroup doesn't exist - create new with filtered rules
        2. RuleGroup exists but event section doesn't - add new section
        3. Both exist - merge rules into existing section

        Args:
            new_rule_group: RuleGroup element to merge.
            force: If True, replace existing duplicate rules.

        Returns:
            Tuple of (added_count, skipped_count).
        """
        group_name = new_rule_group.get("name", "LOLBAS_Detection")
        existing_group = self.find_rule_group(group_name)
        existing_executables = self.get_all_existing_executables()
        existing_cmdline_rules = self.get_all_existing_cmdline_rules()

        is_cmdline_group = "_CMD_" in group_name

        event_section = self._get_first_event_section(new_rule_group)
        if event_section is None:
            return (0, 0)

        event_type = event_section.tag

        if existing_group is None:
            filtered_elements, added, skipped = self._filter_new_rules(event_section, existing_executables, existing_cmdline_rules, is_cmdline_group, force)

            if added > 0:
                new_event_section = etree.Element(event_type, onmatch=event_section.get("onmatch", "include"))
                for elem in filtered_elements:
                    new_event_section.append(elem)

                new_rule_group_clean = etree.Element("RuleGroup", name=group_name, groupRelation="or")
                new_rule_group_clean.append(new_event_section)
                self.insert_rule_group(new_rule_group_clean)

            return (added, skipped)

        existing_event_section = self.find_event_section_in_group(existing_group, event_type)

        if existing_event_section is None:
            filtered_elements, added, skipped = self._filter_new_rules(event_section, existing_executables, existing_cmdline_rules, is_cmdline_group, force)

            if added > 0:
                new_event_section = etree.Element(event_type, onmatch=event_section.get("onmatch", "include"))
                for elem in filtered_elements:
                    new_event_section.append(elem)
                existing_group.append(new_event_section)

            return (added, skipped)

        return self._merge_into_existing_section(existing_event_section, event_section, existing_executables, existing_cmdline_rules, is_cmdline_group, force)

    def _get_first_event_section(self, rule_group: etree._Element) -> etree._Element | None:
        """
        Get the first event type section from a RuleGroup.

        Args:
            rule_group: RuleGroup element to search.

        Returns:
            First child element that is an event section, or None.
        """
        for child in rule_group:
            if isinstance(child.tag, str) and child.tag not in ("RuleGroup",):
                return child
        return None

    def _is_duplicate(
        self,
        element: etree._Element,
        existing_executables: set[str],
        existing_cmdline_rules: dict[str, list[set[str]]],
        is_cmdline_group: bool,
    ) -> tuple[bool, str | None, str | None]:
        """
        Check if a rule element is a duplicate of an existing rule.

        For CommandLine rules, checks if same executable + flags combo exists.
        For fallback rules, checks if executable name exists anywhere.

        Args:
            element: Rule element to check.
            existing_executables: Set of existing executable names.
            existing_cmdline_rules: Dict of existing cmdline rules.
            is_cmdline_group: Whether checking a CommandLine rule group.

        Returns:
            Tuple of (is_duplicate, exec_name, flags_str).
        """
        if element.tag == "Rule" and element.get("groupRelation") == "and":
            exec_name, new_flags = self._extract_rule_info(element)
            if not exec_name:
                return (False, None, None)

            exec_lower = exec_name.lower()
            flags_str = ";".join(sorted(new_flags)) if new_flags else None
            if exec_lower in existing_cmdline_rules:
                for existing_flags_set in existing_cmdline_rules[exec_lower]:
                    if new_flags == existing_flags_set:
                        return (True, exec_name, flags_str)
            return (False, exec_name, flags_str)
        else:
            exec_name = self._get_exec_name_from_element(element)
            if exec_name and exec_name.lower() in existing_executables:
                return (True, exec_name, None)
            return (False, exec_name, None)

    def _extract_rule_info(self, rule: etree._Element) -> tuple[str | None, set[str]]:
        """
        Extract executable name and flags from a compound Rule.

        Args:
            rule: Rule element with groupRelation="and".

        Returns:
            Tuple of (executable_name, set_of_flags).
        """
        exec_name: str | None = None
        flags: set[str] = set()

        for child in rule:
            if child.tag in EXECUTABLE_TAGS and child.text:
                exec_name = child.text.split("\\")[-1]
            elif child.tag == "CommandLine" and child.text:
                flags = set(f.lower().strip() for f in child.text.split(";"))

        return (exec_name, flags)

    def _filter_new_rules(
        self,
        new_section: etree._Element,
        existing_executables: set[str],
        existing_cmdline_rules: dict[str, list[set[str]]],
        is_cmdline_group: bool,
        force: bool,
    ) -> tuple[list[etree._Element], int, int]:
        """
        Filter new rules, removing duplicates unless force is True.

        Processes rules and their associated comments together,
        keeping pairs intact.

        Args:
            new_section: Event section with new rules.
            existing_executables: Set of existing executable names.
            existing_cmdline_rules: Dict of existing cmdline rules.
            is_cmdline_group: Whether processing CommandLine rules.
            force: If True, include duplicates for replacement.

        Returns:
            Tuple of (filtered_elements, added_count, skipped_count).
        """
        filtered: list[etree._Element] = []
        added = 0
        skipped = 0

        children = list(new_section)
        i = 0
        while i < len(children):
            child = children[i]

            if isinstance(child, etree._Comment):
                if i + 1 < len(children):
                    next_child = children[i + 1]
                    if isinstance(next_child.tag, str):
                        is_dup, exec_name, flags_str = self._is_duplicate(next_child, existing_executables, existing_cmdline_rules, is_cmdline_group)
                        if is_dup:
                            if force:
                                filtered.append(child)
                                filtered.append(next_child)
                                added += 1
                                self.logger.debug(f"Will replace rule for {exec_name}")
                            else:
                                skipped += 1
                                self._log_skip(exec_name, flags_str)
                            i += 2
                            continue
                        filtered.append(child)
                        filtered.append(next_child)
                        added += 1
                        i += 2
                        continue
                i += 1
            elif isinstance(child.tag, str):
                is_dup, exec_name, flags_str = self._is_duplicate(child, existing_executables, existing_cmdline_rules, is_cmdline_group)
                if is_dup:
                    if force:
                        filtered.append(child)
                        added += 1
                        self.logger.debug(f"Will replace rule for {exec_name}")
                    else:
                        skipped += 1
                        self._log_skip(exec_name, flags_str)
                else:
                    filtered.append(child)
                    added += 1
                i += 1
            else:
                i += 1

        return (filtered, added, skipped)

    def _log_skip(self, exec_name: str | None, flags_str: str | None) -> None:
        """
        Log a debug message when skipping a duplicate rule.

        Args:
            exec_name: Name of the executable.
            flags_str: Semicolon-joined flags, or None for fallback rules.
        """
        if flags_str:
            self.logger.debug(f"Rule for '{exec_name}' with args [{flags_str}] already exists, skipping")
        else:
            self.logger.debug(f"Rule for '{exec_name}' (fallback, no args) already exists, skipping")

    def _merge_into_existing_section(
        self,
        existing_section: etree._Element,
        new_section: etree._Element,
        existing_executables: set[str],
        existing_cmdline_rules: dict[str, list[set[str]]],
        is_cmdline_group: bool,
        force: bool,
    ) -> tuple[int, int]:
        """
        Merge new rules into an existing event section.

        Appends non-duplicate rules to the existing section.
        If force=True, removes existing duplicates before adding new ones.

        Args:
            existing_section: Existing event section element.
            new_section: New event section with rules to merge.
            existing_executables: Set of existing executable names.
            existing_cmdline_rules: Dict of existing cmdline rules.
            is_cmdline_group: Whether processing CommandLine rules.
            force: If True, replace existing duplicates.

        Returns:
            Tuple of (added_count, skipped_count).
        """
        added = 0
        skipped = 0

        children = list(new_section)
        i = 0
        while i < len(children):
            child = children[i]

            if isinstance(child, etree._Comment):
                if i + 1 < len(children):
                    next_child = children[i + 1]
                    if isinstance(next_child.tag, str):
                        is_dup, exec_name, flags_str = self._is_duplicate(next_child, existing_executables, existing_cmdline_rules, is_cmdline_group)
                        if is_dup:
                            if force:
                                self._remove_existing_rule_globally(exec_name, is_cmdline_group, next_child)
                                existing_section.append(child)
                                existing_section.append(next_child)
                                added += 1
                                self.logger.debug(f"Replaced rule for {exec_name}")
                            else:
                                skipped += 1
                                self._log_skip(exec_name, flags_str)
                            i += 2
                            continue
                        existing_section.append(child)
                        existing_section.append(next_child)
                        added += 1
                        i += 2
                        continue
                i += 1
            elif isinstance(child.tag, str):
                is_dup, exec_name, flags_str = self._is_duplicate(child, existing_executables, existing_cmdline_rules, is_cmdline_group)
                if is_dup:
                    if force:
                        self._remove_existing_rule_globally(exec_name, is_cmdline_group, child)
                        existing_section.append(child)
                        added += 1
                        self.logger.debug(f"Replaced rule for {exec_name}")
                    else:
                        skipped += 1
                        self._log_skip(exec_name, flags_str)
                else:
                    existing_section.append(child)
                    added += 1
                i += 1
            else:
                i += 1

        return (added, skipped)

    def _get_exec_name_from_element(self, element: etree._Element) -> str | None:
        """
        Extract executable name from an element.

        Args:
            element: Element with executable tag (Image, OriginalFileName, etc.)

        Returns:
            Executable filename, or None if not extractable.
        """
        if element.tag in EXECUTABLE_TAGS and element.text:
            return element.text.split("\\")[-1]
        return None

    def _remove_existing_rule_globally(self, exec_name: str | None, is_cmdline_group: bool, new_element: etree._Element | None = None) -> None:
        """
        Remove an existing rule from anywhere in the config.

        Used when force=True to replace existing rules.
        For cmdline groups, matches by executable + flags.
        For fallback groups, matches by executable name only.

        Args:
            exec_name: Executable name to match.
            is_cmdline_group: Whether removing from cmdline group.
            new_element: New element (for flag extraction in cmdline rules).
        """
        if self.root is None or exec_name is None:
            return

        exec_name_lower = exec_name.lower()

        if is_cmdline_group:
            new_flags: set[str] = set()
            if new_element is not None and new_element.tag == "Rule":
                _, new_flags = self._extract_rule_info(new_element)

            for rule in list(self.root.iter("Rule")):
                if rule.get("groupRelation") != "and":
                    continue
                rule_exec, rule_flags = self._extract_rule_info(rule)
                if rule_exec and rule_exec.lower() == exec_name_lower:
                    if new_flags and rule_flags == new_flags:
                        parent = rule.getparent()
                        if parent is not None:
                            self._remove_with_comment(parent, rule)
        else:
            for tag in EXECUTABLE_TAGS:
                for elem in list(self.root.iter(tag)):
                    if elem.getparent() is not None and elem.getparent().tag == "Rule":
                        continue
                    child_exec = self._get_exec_name_from_element(elem)
                    if child_exec and child_exec.lower() == exec_name_lower:
                        parent = elem.getparent()
                        if parent is not None:
                            self._remove_with_comment(parent, elem)

    def _remove_with_comment(self, parent: etree._Element, elem: etree._Element) -> None:
        """
        Remove an element and its preceding comment if present.

        Args:
            parent: Parent element containing the element to remove.
            elem: Element to remove.
        """
        idx = list(parent).index(elem)
        if idx > 0:
            prev = list(parent)[idx - 1]
            if isinstance(prev, etree._Comment):
                parent.remove(prev)
        parent.remove(elem)

    def save(self, output_path: str) -> None:
        """
        Save the modified config to a file.

        Args:
            output_path: Path to save the XML file.

        Raises:
            ValueError: If no config has been loaded.
            OSError: If file writing fails.
        """
        if self.tree is None or self.root is None:
            raise ValueError("No config loaded")

        etree.indent(self.root, space="  ")

        self.tree.write(output_path, pretty_print=True, xml_declaration=True, encoding="utf-8")
        self.logger.info(f"Saved config to {output_path}")
