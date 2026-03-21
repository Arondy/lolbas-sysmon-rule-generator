"""
Data models for LOLBAS entries.

This module defines dataclasses representing LOLBin (Living Off The Land Binary)
entries from the LOLBAS project, including their commands, categories, and
associated MITRE ATT&CK technique mappings.

Also includes Sigma detection rule models for enhanced rule generation.
"""

import re
from dataclasses import dataclass, field


@dataclass
class MitreInfo:
    """
    MITRE ATT&CK technique information.

    Attributes:
        technique_id: MITRE technique ID (e.g., "T1218", "T1218.011").
        technique_name: Human-readable technique name.
    """

    technique_id: str
    technique_name: str


@dataclass
class Command:
    """
    A command example from a LOLBin entry.

    Represents a specific usage example of a LOLBin, including the
    command line, description, associated MITRE technique, and category.

    Attributes:
        command: The full command-line example.
        description: Human-readable description of what the command does.
        mitre_id: Associated MITRE ATT&CK technique ID, or None.
        category: LOLBAS category (e.g., "Execute", "Download", "Dump").
    """

    command: str
    description: str
    mitre_id: str | None
    category: str

    def extract_flags(self) -> list[str]:
        """
        Extract command-line flags/switches from the command.

        Parses the command string to identify flags (arguments starting
        with '-' or '/'), filtering out URLs, file paths, environment
        variables, and other non-flag tokens.

        Returns:
            List of unique lowercase flags, preserving order of first occurrence.
            Example: ["-enc", "-nop", "/c"] for a PowerShell command.
        """
        cmd = self.command
        # Remove URLs
        cmd = re.sub(r'https?://\S+', '', cmd)
        # Remove Windows paths (C:\...)
        cmd = re.sub(r'[A-Za-z]:\\[^\s"\']+', '', cmd)
        # Remove UNC paths (\\server\...)
        cmd = re.sub(r'\\\\[^\s"\']+', '', cmd)
        # Remove environment variables (%VAR%)
        cmd = re.sub(r'%[^%]+%', '', cmd)
        # Remove PowerShell variables ($var)
        cmd = re.sub(r'\$[A-Za-z_][A-Za-z0-9_]*', '', cmd)
        # Remove template placeholders ({...})
        cmd = re.sub(r'\{[^}]+\}', '', cmd)

        # Tokenize, preserving quoted strings
        tokens = re.findall(r'[^\s"\']+|"[^"]*"|\'[^"]*\'', cmd)
        flags: list[str] = []

        for token in tokens:
            token = token.strip('"\'')
            # Only process flags (start with - or /)
            if not (token.startswith('-') or token.startswith('/')):
                continue
            # Extract flag name (before : or =)
            flag = re.split(r'[:=]', token)[0]
            # Skip single-char flags and numeric-only flags
            if len(flag) <= 1:
                continue
            if re.match(r'^[-/]\d+$', flag):
                continue
            flags.append(flag.lower())

        # Return unique flags preserving order
        return list(dict.fromkeys(flags))


@dataclass
class SigmaCondition:
    """
    A single field condition from a Sigma rule.

    Represents one condition like "CommandLine contains 'value'".

    Attributes:
        field: Sysmon field name (e.g., "CommandLine", "Image").
        modifier: Sysmon condition modifier ("is", "contains", "begin with", "end with",
                  "contains all", "contains any").
        values: List of values to match against.
        negated: Whether this condition is negated (NOT).
    """

    field: str
    modifier: str
    values: list[str]
    negated: bool = False


@dataclass
class SigmaDetectionBlock:
    """
    A detection block (selection) from a Sigma rule.

    Represents a group of conditions that are ANDed together.

    Attributes:
        name: Block name from Sigma rule (e.g., "selection_img", "selection_cmd").
        conditions: List of SigmaCondition objects in this block.
    """

    name: str
    conditions: list[SigmaCondition] = field(default_factory=list)


@dataclass
class SigmaRuleBranch:
    """One DNF branch of a Sigma condition expression.

    A branch is interpreted as:
      include_blocks AND NOT exclude_blocks
    Multiple branches are OR'ed together.
    """

    include_blocks: list[str] = field(default_factory=list)
    exclude_blocks: list[str] = field(default_factory=list)


@dataclass
class SigmaDetectionRule:
    """
    A parsed Sigma detection rule.

    Contains all extracted information from a Sigma YAML file
    that is relevant for Sysmon rule generation.

    Attributes:
        title: Rule title for use in XML comments.
        rule_id: Sigma rule UUID.
        level: Detection level (informational, low, medium, high, critical).
        logsource_category: Sigma logsource category (e.g., "process_creation").
        mitre_tags: List of MITRE ATT&CK technique IDs extracted from tags.
        detection_blocks: List of detection blocks (selections).
        condition_expr: Original condition expression string.
        unsupported_fields: Fields that couldn't be mapped to Sysmon.
        unsupported_features: Unsupported Sigma capabilities detected in the rule
            (for example: not, regex, count, near, timeframe, value transforms).
        branches: Condition branches in disjunctive normal form.
        source_url: Original URL where this rule was fetched from.
    """

    title: str
    rule_id: str
    level: str
    logsource_category: str
    mitre_tags: list[str] = field(default_factory=list)
    detection_blocks: list[SigmaDetectionBlock] = field(default_factory=list)
    condition_expr: str = ""
    unsupported_fields: list[str] = field(default_factory=list)
    unsupported_features: list[str] = field(default_factory=list)
    branches: list[SigmaRuleBranch] = field(default_factory=list)
    source_url: str = ""

    def is_convertible(self) -> bool:
        """
        Check if this Sigma rule can be converted to Sysmon.

        A rule is considered convertible only when it has parsed detection
        blocks and does not rely on unsupported fields or unsupported Sigma
        language features.

        Returns:
            True if the rule can be converted safely.
        """
        if not self.detection_blocks:
            return False
        if self.unsupported_fields:
            return False
        if self.unsupported_features:
            return False
        return any(len(block.conditions) > 0 for block in self.detection_blocks)

    def get_mitre_info(self, technique_names: dict[str, str] | None = None) -> list[MitreInfo]:
        """
        Get MITRE ATT&CK technique info from rule tags.

        Args:
            technique_names: Optional mapping of technique IDs to names.

        Returns:
            List of MitreInfo objects.
        """
        names_map = technique_names or {}
        result: list[MitreInfo] = []
        for tid in self.mitre_tags:
            name = names_map.get(tid, tid)
            result.append(MitreInfo(technique_id=tid, technique_name=name))
        return result


@dataclass
class LOLBin:
    """
    A Living Off The Land Binary/Script entry.

    Represents a legitimate system binary or script that can be abused
    for malicious purposes. Contains metadata, command examples, and
    MITRE ATT&CK mappings.

    Attributes:
        name: Executable filename (e.g., "cmd.exe", "certutil.exe").
        original_filename: PE OriginalFileName from version info, or None.
        description: General description of the LOLBin.
        commands: List of command examples with categories.
        mitre_ids: List of associated MITRE ATT&CK technique IDs.
        detection_urls: List of Sigma rule URLs from Detection section.
        sigma_rules: Parsed Sigma detection rules (populated after fetch).
    """

    name: str
    original_filename: str | None
    description: str
    commands: list[Command] = field(default_factory=list)
    mitre_ids: list[str] = field(default_factory=list)
    detection_urls: list[str] = field(default_factory=list)
    sigma_rules: list[SigmaDetectionRule] = field(default_factory=list)

    def has_sigma_rules(self) -> bool:
        """Check if this LOLBin has any parsed Sigma rules."""
        return len(self.sigma_rules) > 0

    def get_convertible_sigma_rules(self) -> list[SigmaDetectionRule]:
        """Get only Sigma rules that can be converted to Sysmon."""
        return [rule for rule in self.sigma_rules if rule.is_convertible()]

    def get_mitre_info_for_category(
        self,
        category: str,
        technique_names: dict[str, str] | None = None,
    ) -> list[MitreInfo]:
        """
        Get MITRE ATT&CK technique info for commands in a specific category.

        Args:
            category: LOLBAS category to filter by (e.g., "Execute").
            technique_names: Optional mapping of technique IDs to names.
                            If not provided, technique ID is used as name.

        Returns:
            List of unique MitreInfo objects for the category.
        """
        mitre_infos: list[MitreInfo] = []
        seen_ids: set[str] = set()
        names_map = technique_names or {}

        for cmd in self.commands:
            if cmd.category == category and cmd.mitre_id and cmd.mitre_id not in seen_ids:
                seen_ids.add(cmd.mitre_id)
                technique_name = names_map.get(cmd.mitre_id, cmd.mitre_id)
                mitre_infos.append(MitreInfo(technique_id=cmd.mitre_id, technique_name=technique_name))

        return mitre_infos

    def get_executable_condition(self) -> tuple[str, str]:
        """
        Get the preferred Sysmon condition for matching this executable.

        Returns:
            Tuple of (tag_name, value) for Sysmon rule matching.
            Uses OriginalFileName if available, otherwise Image path.
        """
        if self.original_filename:
            return ("OriginalFileName", self.original_filename)
        return ("Image", f"\\{self.name}")

    def has_category(self, category: str) -> bool:
        """
        Check if this LOLBin has any commands in the specified category.

        Args:
            category: LOLBAS category to check (e.g., "Download", "Execute").

        Returns:
            True if at least one command belongs to the category.
        """
        return any(cmd.category == category for cmd in self.commands)

    def get_description_for_category(self, category: str) -> str:
        """
        Get a description for this LOLBin in a specific category context.

        Args:
            category: LOLBAS category to get description for.

        Returns:
            First matching command description, or general LOLBin description.
        """
        for cmd in self.commands:
            if cmd.category == category and cmd.description:
                return cmd.description
        return self.description

    def get_all_descriptions_for_category(self, category: str) -> list[str]:
        """
        Get all unique descriptions for commands in a specific category.

        Args:
            category: LOLBAS category to get descriptions for.

        Returns:
            List of unique descriptions from all commands in the category.
        """
        descriptions: list[str] = []
        for cmd in self.commands:
            if cmd.category == category and cmd.description:
                if cmd.description not in descriptions:
                    descriptions.append(cmd.description)
        return descriptions

    def get_command_flags_for_category(self, category: str) -> list[str]:
        """
        Get all unique command-line flags used in commands of a category.

        Aggregates flags from all commands matching the category,
        useful for generating CommandLine detection rules.

        Args:
            category: LOLBAS category to extract flags for.

        Returns:
            List of unique lowercase flags across all matching commands.
        """
        all_flags: list[str] = []
        for cmd in self.commands:
            if cmd.category == category:
                all_flags.extend(cmd.extract_flags())
        return list(dict.fromkeys(all_flags))

    def get_commands_for_category(self, category: str) -> list[Command]:
        """
        Get all commands belonging to a specific category.

        Args:
            category: LOLBAS category to filter by.

        Returns:
            List of Command objects matching the category.
        """
        return [cmd for cmd in self.commands if cmd.category == category]
