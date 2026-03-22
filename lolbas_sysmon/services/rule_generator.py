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
from lolbas_sysmon.models import LOLBin, MitreInfo, SigmaDetectionRule, SigmaRuleBranch
from lolbas_sysmon.services.sigma_converter import LOGSOURCE_MAP

# Event types that support CommandLine field
CMDLINE_SUPPORTED_EVENTS = {"ProcessCreate"}

# Event types that require DLL-only LOLBins
DLL_ONLY_EVENTS = {"ImageLoad"}

# Tags treated as executable identity selectors for Sigma process rules.
SIGMA_EXECUTABLE_BIND_TAGS = {"Image", "OriginalFileName"}


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
        tag_name, _, value = self._resolve_executable_condition(lolbin, event_type)
        return f"{tag_name.lower()}:{value.lower()}"

    def _resolve_executable_condition(self, lolbin: LOLBin, event_type: str) -> tuple[str, str, str]:
        """Resolve the executable condition tag/value pair for a LOLBin/event type."""
        preferred_tag, fallback_tag = self.config.get_condition_tags(event_type)

        if preferred_tag == "OriginalFileName" and lolbin.original_filename:
            return ("OriginalFileName", "is", lolbin.original_filename)
        if preferred_tag == "ImageLoaded":
            return ("ImageLoaded", "end with", f"\\{lolbin.name}")

        tag_name = fallback_tag if preferred_tag == "OriginalFileName" else preferred_tag
        if tag_name is None:
            tag_name = "Image"

        return (tag_name, "end with", f"\\{lolbin.name}")

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

            filtered_lolbins = self._filter_lolbins_for_event_type(lolbins, event_type)
            if not filtered_lolbins:
                continue

            event_element = etree.SubElement(rule_group, event_type, onmatch="include")
            event_element_exclude: etree._Element | None = None
            rules_added = 0
            rules_skipped = 0
            # Always deduplicate exact XML-equivalent CMD rules within one event section.
            # This prevents repeated Sigma branches when the same Sigma rule URL appears
            # across multiple LOLBins in the same category.
            event_include_cmd_signatures: set[str] = set()
            event_exclude_cmd_signatures: set[str] = set()
            merged_include_rules: dict[str, etree._Element] = {}
            merged_include_comments: dict[str, str | None] = {}
            merged_include_order: list[str] = []
            merged_exclude_rules: dict[str, etree._Element] = {}
            merged_exclude_order: list[str] = []

            for lolbin in filtered_lolbins:
                executable_key = self._get_executable_key(lolbin, event_type)
                rule_element = None

                if with_cmdline:
                    include_rules, exclude_rules, include_comments = self._generate_cmdline_rules(lolbin, category, event_type)
                    if not include_rules and not exclude_rules:
                        continue

                    for idx, inc_rule in enumerate(include_rules):
                        if include_comments and idx < len(include_comments):
                            comment_text = include_comments[idx]
                        else:
                            description = lolbin.get_description_for_category(category)
                            comment_text = self._sanitize_comment(description) if description else None

                        merge_sig = self._get_rule_signature_without_executable(inc_rule)
                        if merge_sig in merged_include_rules:
                            self._merge_executable_selectors(merged_include_rules[merge_sig], inc_rule)
                            continue

                        merged_include_rules[merge_sig] = inc_rule
                        merged_include_comments[merge_sig] = comment_text
                        merged_include_order.append(merge_sig)

                    if exclude_rules:
                        for exc_rule in exclude_rules:
                            exc_merge_sig = self._get_rule_signature_without_executable(exc_rule)
                            if exc_merge_sig in merged_exclude_rules:
                                self._merge_executable_selectors(merged_exclude_rules[exc_merge_sig], exc_rule)
                                continue
                            merged_exclude_rules[exc_merge_sig] = exc_rule
                            merged_exclude_order.append(exc_merge_sig)
                else:
                    if unique_rules and self._is_fallback_rule_duplicate(executable_key, event_type):
                        self.logger.debug(f"Skipping duplicate fallback rule: {lolbin.name} (event_type={event_type})")
                        rules_skipped += 1
                        continue

                    rule_element = self._generate_fallback_rule(lolbin, category, event_type)
                    if rule_element is not None and unique_rules:
                        self._mark_fallback_rule_generated(executable_key, event_type)

                if not with_cmdline and rule_element is not None:
                    description = lolbin.get_description_for_category(category)
                    if description:
                        comment = etree.Comment(f" {self._sanitize_comment(description)} ")
                        event_element.append(comment)
                    event_element.append(rule_element)
                    rules_added += 1

            if with_cmdline:
                for merge_sig in merged_include_order:
                    inc_rule = merged_include_rules[merge_sig]
                    flags_key = self._get_cmd_dedup_key(inc_rule)

                    if flags_key in event_include_cmd_signatures:
                        rules_skipped += 1
                        self.logger.debug(f"Skipping duplicate CMD rule in section '{group_name}/{event_type}' (signature={flags_key})")
                        continue

                    if unique_rules and self._is_cmd_rule_duplicate("__merged__", event_type, flags_key):
                        rules_skipped += 1
                        continue

                    event_include_cmd_signatures.add(flags_key)
                    if unique_rules:
                        self._mark_cmd_rule_generated("__merged__", event_type, flags_key)

                    comment_text = merged_include_comments.get(merge_sig)
                    if comment_text:
                        event_element.append(etree.Comment(f" {comment_text} "))
                    event_element.append(inc_rule)
                    rules_added += 1

                for exc_merge_sig in merged_exclude_order:
                    exc_rule = merged_exclude_rules[exc_merge_sig]
                    exc_key = self._get_cmd_dedup_key(exc_rule)
                    if exc_key in event_exclude_cmd_signatures:
                        continue
                    event_exclude_cmd_signatures.add(exc_key)

                    if event_element_exclude is None:
                        event_element_exclude = etree.SubElement(rule_group, event_type, onmatch="exclude")
                    event_element_exclude.append(exc_rule)

            if rules_added == 0:
                rule_group.remove(event_element)
                if event_element_exclude is not None:
                    rule_group.remove(event_element_exclude)
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

    def _get_cmd_dedup_key(self, rule_element: etree._Element) -> str:
        """Build deduplication key for CMD-like rules from all children.

        This is robust for Sigma-based rules that may not always contain
        CommandLine fields.
        """
        parts: list[str] = []
        for child in rule_element:
            if not isinstance(child.tag, str):
                continue
            cond = (child.get("condition") or "").strip().lower()
            text = (child.text or "").strip().lower()
            if ";" in text:
                # Normalize multi-value conditions where order is not semantically
                # important to avoid duplicate branches that differ only by value order.
                items = [x.strip() for x in text.split(";") if x.strip()]
                text = ";".join(sorted(dict.fromkeys(items)))
            parts.append(f"{child.tag.lower()}|{cond}|{text}")
        if not parts:
            return "empty"
        return self._get_flags_key(parts)

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

        if rule_type in ("cmd", "both"):
            for category, lolbins in lolbins_by_category.items():
                if lolbins:
                    cmd_group = self.generate_rule_group(lolbins, category, with_cmdline=True)
                    if cmd_group is not None:
                        rule_groups.append(cmd_group)

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
        tag_name, condition, value = self._resolve_executable_condition(lolbin, event_type)
        rule = etree.Element(tag_name, condition=condition)
        rule.text = value

        mitre_infos = lolbin.get_mitre_info_for_category(category, self.mitre_technique_names)
        if mitre_infos:
            rule.set("name", self._create_mitre_attribute(mitre_infos))

        return rule

    def _generate_cmdline_rules(
        self,
        lolbin: LOLBin,
        category: str,
        event_type: str,
    ) -> tuple[list[etree._Element], list[etree._Element], list[str]]:
        """
        Generate CommandLine rules with executable + flag matching.

        Creates compound rules (groupRelation="and") that match both
        the executable and specific command-line flags. Uses Sigma rules
        if available (priority), otherwise falls back to LOLBAS command examples.

        Args:
            lolbin: LOLBin object to generate rule for.
            category: LOLBAS category for flag extraction and MITRE mapping.
            event_type: Sysmon event type for determining condition tags.

        Returns:
            Tuple: (include_rules, exclude_rules, include_comments).
        """
        sigma_rules = self._get_sigma_rules_for_event(lolbin, event_type)
        if sigma_rules:
            all_include: list[etree._Element] = []
            all_exclude: list[etree._Element] = []
            include_comments: list[str] = []
            for sigma_rule in sigma_rules:
                inc, exc = self._generate_sigma_rules(sigma_rule)
                for inc_rule in inc:
                    self._ensure_sigma_rule_bound_to_lolbin(inc_rule, lolbin, event_type)
                for exc_rule in exc:
                    self._ensure_sigma_rule_bound_to_lolbin(exc_rule, lolbin, event_type)
                all_include.extend(inc)
                all_exclude.extend(exc)
                include_comments.extend(self._create_sigma_branch_comments(sigma_rule, len(inc)))
            if all_include or all_exclude:
                return all_include, all_exclude, include_comments

        flags = lolbin.get_command_flags_for_category(category)
        if not flags:
            return [], [], []

        rule = etree.Element("Rule", groupRelation="and")

        mitre_infos = lolbin.get_mitre_info_for_category(category, self.mitre_technique_names)
        if mitre_infos:
            rule.set("name", self._create_mitre_attribute(mitre_infos))

        tag_name, condition, value = self._resolve_executable_condition(lolbin, event_type)
        image_elem = etree.SubElement(rule, tag_name, condition=condition)
        image_elem.text = value

        cmdline_elem = etree.SubElement(rule, "CommandLine", condition="contains any")
        cmdline_elem.text = ";".join(flags)

        return [rule], [], []

    def _create_sigma_branch_comments(self, sigma_rule: SigmaDetectionRule, branch_count: int) -> list[str]:
        """Create per-branch comments for Sigma-expanded rules.

        First branch gets full metadata comment, subsequent branches receive a
        compact index marker for easier review (for example: "2 - <rule_id>").
        """
        if branch_count <= 0:
            return []

        comments = [self._create_sigma_comment(sigma_rule)]
        if branch_count == 1:
            return comments

        rule_id = sigma_rule.rule_id or "no-id"
        for idx in range(2, branch_count + 1):
            comments.append(self._sanitize_comment(f"{idx} - {rule_id}"))

        return comments

    def _get_sigma_rules_for_event(self, lolbin: LOLBin, event_type: str) -> list[SigmaDetectionRule]:
        """Return all convertible Sigma rules that match the target Sysmon event type."""
        if not lolbin.has_sigma_rules():
            return []

        matching_rules: list[SigmaDetectionRule] = []
        seen_signatures: set[str] = set()
        for sigma_rule in lolbin.get_convertible_sigma_rules():
            sigma_event_type = LOGSOURCE_MAP.get(sigma_rule.logsource_category)
            if sigma_event_type == event_type:
                signature = self._get_sigma_rule_signature(sigma_rule)
                if signature in seen_signatures:
                    continue
                seen_signatures.add(signature)
                matching_rules.append(sigma_rule)

        return matching_rules

    def _get_sigma_rule_signature(self, sigma_rule: SigmaDetectionRule) -> str:
        """Build a stable signature for deduplicating repeated Sigma rules.

        LOLBAS detection lists can reference the same Sigma rule multiple times
        (duplicate URLs, mirrors, or cached variants). We deduplicate rules by
        semantic content to avoid generating the same branch set repeatedly.
        """
        branch_parts: list[str] = []
        for branch in sigma_rule.branches:
            inc = ",".join(sorted(dict.fromkeys(branch.include_blocks)))
            exc = ",".join(sorted(dict.fromkeys(branch.exclude_blocks)))
            branch_parts.append(f"inc:[{inc}]|exc:[{exc}]")

        block_parts: list[str] = []
        for block in sigma_rule.detection_blocks:
            cond_parts: list[str] = []
            for cond in block.conditions:
                values = ";".join(cond.values)
                cond_parts.append(f"{cond.field}|{cond.modifier}|{values}|neg={cond.negated}")
            block_parts.append(f"{block.name}:" + "||".join(cond_parts))

        key_parts = [
            sigma_rule.rule_id or "",
            sigma_rule.title or "",
            sigma_rule.logsource_category or "",
            sigma_rule.condition_expr or "",
            "@@".join(sorted(branch_parts)),
            "@@".join(sorted(block_parts)),
        ]
        return "###".join(key_parts)

    def _generate_sigma_rules(self, sigma_rule: SigmaDetectionRule) -> tuple[list[etree._Element], list[etree._Element]]:
        """Generate include/exclude Sysmon rules from Sigma branches."""
        if not sigma_rule.is_convertible():
            return [], []

        blocks_by_name = {b.name: b for b in sigma_rule.detection_blocks}
        branches = sigma_rule.branches
        if not branches:
            # Backward safety: OR across all blocks if no parsed branches
            branches = [SigmaRuleBranch(include_blocks=[block.name]) for block in sigma_rule.detection_blocks]

        include_rules: list[etree._Element] = []
        exclude_rules: list[etree._Element] = []
        mitre_infos = sigma_rule.get_mitre_info(self.mitre_technique_names)

        for branch in branches:
            include_conditions: list = []
            exclude_conditions: list = []

            for block_name in branch.include_blocks:
                block = blocks_by_name.get(block_name)
                if block:
                    include_conditions.extend(block.conditions)

            for block_name in branch.exclude_blocks:
                block = blocks_by_name.get(block_name)
                if block:
                    exclude_conditions.extend(block.conditions)

            if not include_conditions:
                continue

            include_rules.extend(self._build_sigma_rules_from_conditions(include_conditions, mitre_infos))

            if exclude_conditions:
                # A and not B => include(A), exclude(A and B)
                exclude_rules.extend(self._build_sigma_rules_from_conditions(include_conditions + exclude_conditions, mitre_infos))

        return self._dedup_sigma_rules(include_rules), self._dedup_sigma_rules(exclude_rules)

    def _dedup_sigma_rules(self, rules: list[etree._Element]) -> list[etree._Element]:
        """Remove duplicate Sigma-generated rules within one conversion pass."""
        deduped: list[etree._Element] = []
        seen: set[str] = set()

        for rule in rules:
            sig = self._get_cmd_dedup_key(rule)
            if sig in seen:
                continue
            seen.add(sig)
            deduped.append(rule)

        return deduped

    def _build_sigma_rules_from_conditions(
        self,
        conditions,
        mitre_infos: list[MitreInfo],
    ) -> list[etree._Element]:
        """Build one or more Sysmon rules from Sigma conditions.

        Sigma lists such as "Image|endswith: [a, b]" are OR semantics.
        For conditions that don't support packed multi-values in Sysmon,
        expand them into multiple rule variants.
        """
        variants: list[list[tuple[str, str, str]]] = [[]]

        for cond in conditions:
            if cond.negated:
                # Negation is represented at branch level (exclude section)
                continue
            if not cond.values:
                continue

            sysmon_condition = self._sigma_condition_to_sysmon(cond.modifier)
            value_options: list[str]

            if sysmon_condition in ("contains any", "contains all"):
                value_options = [self._format_values_for_condition(cond.values, sysmon_condition)]
            else:
                # Preserve OR semantics for non-packed conditions by branching.
                value_options = cond.values

            next_variants: list[list[tuple[str, str, str]]] = []
            for variant in variants:
                for value in value_options:
                    next_variants.append(variant + [(cond.field, sysmon_condition, value)])
            variants = next_variants

        rules: list[etree._Element] = []
        for variant in variants:
            if not variant:
                continue

            rule = etree.Element("Rule", groupRelation="and")
            if mitre_infos:
                rule.set("name", self._create_mitre_attribute(mitre_infos))

            for field, condition, value in variant:
                elem = etree.SubElement(rule, field, condition=condition)
                elem.text = value

            if len(rule) > 0:
                rules.append(rule)

        return rules

    def _ensure_sigma_rule_bound_to_lolbin(
        self,
        rule: etree._Element,
        lolbin: LOLBin,
        event_type: str,
    ) -> None:
        """Ensure Sigma-derived rule is scoped to the current LOLBin.

        If the Sigma rule has no Image/OriginalFileName selector, add one
        based on LOLBAS executable metadata to avoid overly broad matches.
        """
        if any(isinstance(child.tag, str) and child.tag in SIGMA_EXECUTABLE_BIND_TAGS for child in rule):
            return

        tag_name, condition, value = self._resolve_executable_condition(lolbin, event_type)
        exec_elem = etree.Element(tag_name, condition=condition)
        exec_elem.text = value
        rule.insert(0, exec_elem)

    def _get_rule_signature_without_executable(self, rule: etree._Element) -> str:
        """Build a stable signature for grouping rules by non-executable logic."""
        parts: list[str] = []
        for child in rule:
            if not isinstance(child.tag, str):
                continue
            if child.tag in SIGMA_EXECUTABLE_BIND_TAGS:
                continue
            cond = (child.get("condition") or "").strip().lower()
            text = (child.text or "").strip().lower()
            if ";" in text:
                items = [x.strip() for x in text.split(";") if x.strip()]
                text = ";".join(sorted(dict.fromkeys(items)))
            parts.append(f"{child.tag.lower()}|{cond}|{text}")
        if not parts:
            return "only-executable"
        return "||".join(sorted(parts))

    def _merge_executable_selectors(self, target_rule: etree._Element, source_rule: etree._Element) -> None:
        """Merge executable selectors from source_rule into target_rule as OR lists."""
        for source_child in source_rule:
            if not isinstance(source_child.tag, str):
                continue
            if source_child.tag not in SIGMA_EXECUTABLE_BIND_TAGS:
                continue

            source_cond = source_child.get("condition") or ""
            source_text = (source_child.text or "").strip()
            if not source_text:
                continue

            target_match: etree._Element | None = None
            for target_child in target_rule:
                if not isinstance(target_child.tag, str):
                    continue
                if target_child.tag == source_child.tag and (target_child.get("condition") or "") == source_cond:
                    target_match = target_child
                    break

            if target_match is None:
                target_match = etree.Element(source_child.tag, condition=source_cond)
                target_match.text = source_text
                target_rule.insert(0, target_match)
                continue

            existing_values = [x.strip() for x in (target_match.text or "").split(";") if x.strip()]
            existing_lower = {x.lower() for x in existing_values}
            if source_text.lower() not in existing_lower:
                existing_values.append(source_text)
                target_match.text = ";".join(existing_values)

    def _sigma_condition_to_sysmon(self, modifier: str) -> str:
        """Map Sigma modifier to Sysmon condition attribute."""
        mapping = {
            "is": "is",
            "contains": "contains",
            "begin with": "begin with",
            "end with": "end with",
            "contains all": "contains all",
            "contains any": "contains any",
        }
        return mapping.get(modifier, "is")

    def _format_values_for_condition(self, values: list[str], condition: str) -> str:
        """Format Sigma values for Sysmon XML text."""
        if condition in ("contains any", "contains all"):
            return ";".join(values)
        return values[0]

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

    def _create_sigma_comment(self, sigma_rule: SigmaDetectionRule) -> str:
        """
        Create XML comment text from Sigma rule metadata.

        Args:
            sigma_rule: Sigma rule with title, level, rule_id.

        Returns:
            Formatted comment string with Sigma metadata.
        """
        parts = [f"Sigma: {sigma_rule.title}"]
        if sigma_rule.level:
            parts.append(f"Level: {sigma_rule.level}")
        if sigma_rule.rule_id:
            parts.append(f"ID: {sigma_rule.rule_id}")
        comment = " | ".join(parts)
        return self._sanitize_comment(comment)

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
