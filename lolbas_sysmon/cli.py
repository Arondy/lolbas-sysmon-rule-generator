"""
Command-line interface for LOLBAS Sysmon Rule Generator.

This module provides the CLI entry point for generating Sysmon detection rules
based on LOLBAS (Living Off The Land Binaries and Scripts) data. It supports
standalone rule generation, merging with existing Sysmon configs, and dry-run mode.
"""

import argparse
import json
from dataclasses import dataclass, field
from pathlib import Path

import httpx
from lxml import etree

from lolbas_sysmon.config import Config, ConfigLoader, logger
from lolbas_sysmon.config.settings import DEFAULT_OUTPUT_FILE
from lolbas_sysmon.models import LOLBin
from lolbas_sysmon.services import (
    EXECUTABLE_TAGS,
    LOLBASClient,
    LOLBASParser,
    MitreClient,
    SigmaClient,
    SigmaConverter,
    SysmonConfigManager,
    SysmonRuleGenerator,
)


@dataclass
class SigmaEnrichmentStats:
    """Statistics for Sigma rule enrichment process."""

    urls_total: int = 0
    urls_downloaded: int = 0
    urls_cached: int = 0
    urls_failed: int = 0
    rules_parsed: int = 0
    rules_convertible: int = 0
    rules_skipped_fields: int = 0
    rules_skipped_features: int = 0
    lolbins_enriched: int = 0
    skipped_reasons: dict[str, int] = field(default_factory=dict)

    def log_summary(self, log_func) -> None:
        """Log a formatted summary of enrichment statistics."""
        log_func("Sigma enrichment summary:")
        log_func(f"  URLs: {self.urls_total} total, {self.urls_downloaded} downloaded, {self.urls_cached} cached, {self.urls_failed} failed")
        log_func(f"  Rules: {self.rules_parsed} parsed, {self.rules_convertible} convertible")
        log_func(f"  Skipped: {self.rules_skipped_fields} (unsupported fields), {self.rules_skipped_features} (unsupported features)")
        log_func(f"  LOLBins enriched: {self.lolbins_enriched}")

        if self.skipped_reasons:
            top_reasons = sorted(self.skipped_reasons.items(), key=lambda x: -x[1])[:5]
            reasons_str = ", ".join(f"{reason}: {count}" for reason, count in top_reasons)
            log_func(f"  Top skip reasons: {reasons_str}")


class CLI:
    """
    Command-line interface handler for LOLBAS Sysmon rule generation.

    This class orchestrates the entire rule generation process including:
    - Parsing command-line arguments
    - Loading configuration from TOML files
    - Fetching LOLBAS and MITRE ATT&CK data
    - Generating Sysmon detection rules
    - Merging rules with existing configs or saving standalone

    Attributes:
        logger: Loguru logger instance bound to this class.
        parser: ArgumentParser instance for CLI argument handling.
    """

    def __init__(self) -> None:
        """Initialize CLI with logger and argument parser."""
        self.logger = logger.bind(class_name=self.__class__.__name__)
        self.parser = self._create_parser()

    def _create_parser(self) -> argparse.ArgumentParser:
        """
        Create and configure the argument parser.

        Returns:
            Configured ArgumentParser with all supported CLI arguments.
        """
        parser = argparse.ArgumentParser(
            prog="lolbas_sysmon",
            description="Generate Sysmon detection rules from LOLBAS data",
        )
        parser.add_argument(
            "-i",
            "--input",
            type=str,
            default=None,
            help="Input Sysmon config XML file to merge with",
        )
        parser.add_argument(
            "-o",
            "--output",
            type=str,
            default=DEFAULT_OUTPUT_FILE,
            help=f"Output XML file path (default: {DEFAULT_OUTPUT_FILE})",
        )
        parser.add_argument(
            "-f",
            "--force",
            action="store_true",
            help="Replace existing rules instead of skipping",
        )
        parser.add_argument(
            "-c",
            "--config",
            type=str,
            default=None,
            help="Path to TOML configuration file",
        )
        parser.add_argument(
            "--category",
            type=str,
            default=None,
            help="Comma-separated list of categories to generate (e.g., Execute,Dump)",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Print generated rules without saving to file",
        )
        parser.add_argument(
            "--lolbas-json",
            type=str,
            default=None,
            help="Path to local LOLBAS JSON file",
        )
        parser.add_argument(
            "--mitre-json",
            type=str,
            default=None,
            help="Path to local MITRE ATT&CK JSON file",
        )
        parser.add_argument(
            "--unique-rules",
            action="store_true",
            help="Skip duplicate rules for same executable within same event type",
        )
        parser.add_argument(
            "--coverage",
            action="store_true",
            help="Analyze LOLBAS coverage in existing Sysmon config (requires -i)",
        )
        parser.add_argument(
            "--show-missing",
            action="store_true",
            help="Show list of LOLBins missing from config (use with --coverage)",
        )
        parser.add_argument(
            "--show-covered",
            action="store_true",
            help="Show list of LOLBins covered in config (use with --coverage)",
        )

        rule_type_group = parser.add_mutually_exclusive_group()
        rule_type_group.add_argument(
            "--only-cmd",
            action="store_true",
            help="Generate only CommandLine rules (more specific)",
        )
        rule_type_group.add_argument(
            "--only-fallback",
            action="store_true",
            help="Generate only fallback rules (executable name only)",
        )
        parser.add_argument(
            "--update-data",
            action="store_true",
            help="Force re-download of LOLBAS, MITRE, and Sigma data",
        )
        parser.add_argument(
            "--update-lolbas",
            action="store_true",
            help="Force re-download of LOLBAS JSON data from URL",
        )
        parser.add_argument(
            "--update-mitre",
            action="store_true",
            help="Force re-download of MITRE ATT&CK JSON data from URL",
        )
        parser.add_argument(
            "--no-sigma",
            action="store_true",
            help="Disable Sigma-based rule enrichment",
        )
        parser.add_argument(
            "--update-sigma",
            action="store_true",
            help="Force re-download of cached Sigma rules",
        )
        return parser

    def run(self, args: list[str] | None = None) -> int:
        """
        Execute the CLI workflow.

        This is the main entry point that orchestrates:
        1. Argument parsing and validation
        2. Configuration loading
        3. MITRE ATT&CK data loading
        4. LOLBAS data fetching/loading
        5. Sigma enrichment (if enabled)
        6. Rule generation
        7. Output (dry-run, merge, or standalone save)

        Args:
            args: Optional list of CLI arguments. If None, sys.argv is used.

        Returns:
            Exit code: 0 for success, 1 for errors.
        """
        parsed_args = self.parser.parse_args(args)

        if parsed_args.coverage:
            return self._run_coverage_analysis(parsed_args)

        self.logger.info("Starting LOLBAS Sysmon Rule Generator")

        # Validate input files
        if error := self._validate_input_files(parsed_args):
            return error

        # Load configuration
        config = self._load_config(parsed_args)
        if config is None:
            return 1

        # Log update flags
        self._log_update_flags(parsed_args)

        # Load MITRE data
        mitre_technique_names = self._load_mitre_data(
            config,
            parsed_args.mitre_json,
            force_update=parsed_args.update_data or parsed_args.update_mitre,
        )

        # Load LOLBAS data
        lolbins = self._load_lolbas_data(config, parsed_args)
        if lolbins is None:
            return 1

        # Sigma enrichment
        use_sigma = config.sigma.enabled and not parsed_args.no_sigma
        if use_sigma:
            force_update_sigma = parsed_args.update_data or parsed_args.update_sigma
            self._enrich_with_sigma(lolbins, config, force_update=force_update_sigma)
        else:
            self.logger.info("Sigma enrichment disabled")

        # Generate and output rules
        return self._generate_and_output(config, lolbins, mitre_technique_names, parsed_args)

    def _validate_input_files(self, parsed_args) -> int | None:
        """
        Validate that specified input files exist.

        Args:
            parsed_args: Parsed command-line arguments.

        Returns:
            Error code 1 if validation fails, None if all files exist.
        """
        if parsed_args.input and not Path(parsed_args.input).exists():
            self.logger.error(f"Input file not found: {parsed_args.input}")
            return 1

        # In force-update mode, custom JSON path may be used as a new save target.
        require_lolbas_file = not (parsed_args.update_data or parsed_args.update_lolbas)
        if require_lolbas_file and parsed_args.lolbas_json and not Path(parsed_args.lolbas_json).exists():
            self.logger.error(f"LOLBAS JSON file not found: {parsed_args.lolbas_json}")
            return 1

        # In force-update mode, custom JSON path may be used as a new save target.
        require_mitre_file = not (parsed_args.update_data or parsed_args.update_mitre)
        if require_mitre_file and parsed_args.mitre_json and not Path(parsed_args.mitre_json).exists():
            self.logger.error(f"MITRE JSON file not found: {parsed_args.mitre_json}")
            return 1

        return None

    def _load_config(self, parsed_args) -> Config | None:
        """
        Load and configure the application config.

        Loads from TOML file, applies CLI overrides for categories
        and unique_rules flag.

        Args:
            parsed_args: Parsed command-line arguments.

        Returns:
            Configured Config object, or None on error.
        """
        config_loader = ConfigLoader()
        try:
            config = config_loader.load(parsed_args.config)
        except FileNotFoundError as e:
            self.logger.error(str(e))
            return None

        # Override categories from CLI
        if parsed_args.category:
            categories = [c.strip() for c in parsed_args.category.split(",")]
            for cat in categories:
                if cat not in config.categories:
                    self.logger.warning(f"Category '{cat}' is not in enabled categories from config")
            config.categories = categories

        # Override unique_rules from CLI
        if parsed_args.unique_rules:
            config.unique_rules = True

        self.logger.info(f"Categories: {', '.join(config.categories)}")
        if config.unique_rules:
            self.logger.info("Unique rules mode enabled: skipping duplicates")

        return config

    def _log_update_flags(self, parsed_args) -> None:
        """Log which data sources will be force-updated."""
        force_update_all = parsed_args.update_data
        force_update_lolbas = force_update_all or parsed_args.update_lolbas
        force_update_mitre = force_update_all or parsed_args.update_mitre
        force_update_sigma = force_update_all or parsed_args.update_sigma

        if force_update_all:
            self.logger.info("Force update mode: re-downloading LOLBAS, MITRE, and Sigma data")
        else:
            if force_update_lolbas:
                self.logger.info("Force update mode: re-downloading LOLBAS data")
            if force_update_mitre:
                self.logger.info("Force update mode: re-downloading MITRE data")
            if force_update_sigma:
                self.logger.info("Force update mode: re-downloading Sigma data")

    def _load_lolbas_data(self, config: Config, parsed_args) -> list[LOLBin] | None:
        """
        Load and parse LOLBAS data.

        Fetches from URL or loads from local file, then parses into LOLBin objects.

        Args:
            config: Application configuration.
            parsed_args: Parsed command-line arguments.

        Returns:
            List of parsed LOLBin objects, or None on error.
        """
        force_update_lolbas = parsed_args.update_data or parsed_args.update_lolbas

        try:
            client = LOLBASClient(url=config.lolbas.url, default_json=config.lolbas.json_file)
            if force_update_lolbas:
                save_path = parsed_args.lolbas_json or config.lolbas.json_file
                raw_data = client.fetch_lolbas_data(save_path=save_path)
            else:
                raw_data = client.get_lolbas_data(
                    parsed_args.lolbas_json,
                    auto_update=config.lolbas.auto_update,
                    max_age_days=config.lolbas.max_age_days,
                )
        except FileNotFoundError as e:
            self.logger.error(f"LOLBAS JSON file not found: {e}")
            return None
        except json.JSONDecodeError as e:
            self.logger.error(f"Invalid JSON in LOLBAS file: {e}")
            return None
        except httpx.HTTPError as e:
            self.logger.error(f"Failed to fetch LOLBAS data: {e}")
            return None

        lolbas_parser = LOLBASParser()
        return lolbas_parser.parse(raw_data)

    def _generate_and_output(
        self,
        config: Config,
        lolbins: list[LOLBin],
        mitre_technique_names: dict[str, str],
        parsed_args,
    ) -> int:
        """
        Generate rules and handle output (dry-run, merge, or standalone save).

        Args:
            config: Application configuration.
            lolbins: List of parsed LOLBin objects.
            mitre_technique_names: MITRE technique ID to name mapping.
            parsed_args: Parsed command-line arguments.

        Returns:
            Exit code: 0 for success, 1 for errors.
        """
        # Filter LOLBins by category
        lolbas_parser = LOLBASParser()
        lolbins_by_category: dict[str, list[LOLBin]] = {}

        for category in config.categories:
            filtered = lolbas_parser.filter_by_category(lolbins, category)
            if filtered:
                lolbins_by_category[category] = filtered
            else:
                self.logger.warning(f"No LOLBins found with category '{category}'")

        if not lolbins_by_category:
            self.logger.warning("No LOLBins found for any specified category")
            return 0

        # Generate rules
        generator = SysmonRuleGenerator(config, mitre_technique_names)

        if parsed_args.only_cmd:
            rule_type = "cmd"
            self.logger.info("Generating only CommandLine rules")
        elif parsed_args.only_fallback:
            rule_type = "fallback"
            self.logger.info("Generating only fallback rules")
        else:
            rule_type = "both"

        rule_groups = generator.generate_all_rule_groups(lolbins_by_category, rule_type=rule_type)

        # Output
        if parsed_args.dry_run:
            return self._dry_run(rule_groups, generator)

        if parsed_args.input:
            return self._merge_with_existing(
                parsed_args.input,
                parsed_args.output,
                rule_groups,
                parsed_args.force,
            )
        else:
            sysmon_config = generator.create_sysmon_config(rule_groups)
            return self._save_standalone(parsed_args.output, sysmon_config, generator)

    def _load_mitre_data(
        self,
        config: Config,
        mitre_json_arg: str | None,
        force_update: bool = False,
    ) -> dict[str, str]:
        """
        Load MITRE ATT&CK technique names mapping.

        Attempts to load from local file first, falls back to URL fetch.
        If all sources fail, returns empty dict (technique IDs used as names).

        Args:
            config: Application configuration with MITRE settings.
            mitre_json_arg: Optional custom path to MITRE JSON file.
            force_update: If True, force re-download from URL.

        Returns:
            Dictionary mapping technique IDs to human-readable names.
        """
        mitre_client = MitreClient(url=config.mitre.url, default_json=config.mitre.json_file)

        if force_update:
            try:
                save_path = mitre_json_arg or config.mitre.json_file
                return mitre_client.fetch_from_url(save_path=save_path)
            except httpx.HTTPError as e:
                self.logger.warning(f"Failed to fetch MITRE data: {e}, using technique IDs as names")
                return {}

        if mitre_json_arg:
            custom_path = mitre_json_arg
            try:
                return mitre_client.get_technique_names(
                    custom_path,
                    auto_update=config.mitre.auto_update,
                    max_age_days=config.mitre.max_age_days,
                )
            except FileNotFoundError:
                self.logger.warning(f"MITRE JSON file '{custom_path}' not found, fetching from URL")
            except json.JSONDecodeError as e:
                self.logger.warning(f"Invalid MITRE JSON file '{custom_path}': {e}, fetching from URL")

            try:
                return mitre_client.fetch_from_url(save_path=custom_path)
            except httpx.HTTPError as e:
                self.logger.warning(f"Failed to fetch MITRE data: {e}, using technique IDs as names")
                return {}

        try:
            return mitre_client.get_technique_names(
                auto_update=config.mitre.auto_update,
                max_age_days=config.mitre.max_age_days,
            )
        except json.JSONDecodeError as e:
            self.logger.warning(f"Invalid MITRE JSON file '{config.mitre.json_file}': {e}, fetching from URL")
        except FileNotFoundError:
            self.logger.warning(f"MITRE JSON file '{config.mitre.json_file}' not found, fetching from URL")

        try:
            return mitre_client.fetch_from_url(save_path=config.mitre.json_file)
        except httpx.HTTPError as e:
            self.logger.warning(f"Failed to fetch MITRE data: {e}, using technique IDs as names")
            return {}

    def _enrich_with_sigma(
        self,
        lolbins: list[LOLBin],
        config: Config,
        force_update: bool = False,
    ) -> SigmaEnrichmentStats:
        """
        Enrich LOLBins with parsed Sigma detection rules.

        Downloads Sigma rules referenced in LOLBAS Detection sections,
        parses them, and attaches convertible rules to LOLBin objects.

        Args:
            lolbins: Parsed LOLBin objects to enrich.
            config: Loaded application config with Sigma settings.
            force_update: If True, ignore cache and re-download Sigma rules.

        Returns:
            SigmaEnrichmentStats with detailed statistics.
        """
        stats = SigmaEnrichmentStats()
        sigma_client = SigmaClient(cache_dir=config.sigma.cache_dir)
        sigma_converter = SigmaConverter()

        for lolbin in lolbins:
            if not lolbin.detection_urls:
                continue

            lolbin_got_rule = False

            for url in lolbin.detection_urls:
                if not SigmaClient.is_sigma_url(url):
                    continue

                stats.urls_total += 1

                path, from_cache = sigma_client.download_rule(
                    url,
                    force=force_update,
                    auto_update=config.sigma.auto_update,
                    max_age_days=config.sigma.max_age_days,
                )

                if path is None:
                    stats.urls_failed += 1
                    continue

                if from_cache:
                    stats.urls_cached += 1
                else:
                    stats.urls_downloaded += 1

                sigma_rule = sigma_converter.parse_rule(path, source_url=url)
                if sigma_rule is None:
                    continue

                stats.rules_parsed += 1

                if sigma_converter.is_rule_convertible(sigma_rule):
                    stats.rules_convertible += 1
                    lolbin.sigma_rules.append(sigma_rule)
                    lolbin_got_rule = True
                else:
                    # Track skip reasons
                    if sigma_rule.unsupported_fields:
                        stats.rules_skipped_fields += 1
                        for field_name in sigma_rule.unsupported_fields:
                            reason = f"field:{field_name}"
                            stats.skipped_reasons[reason] = stats.skipped_reasons.get(reason, 0) + 1

                    if sigma_rule.unsupported_features:
                        stats.rules_skipped_features += 1
                        for feature in sigma_rule.unsupported_features:
                            reason = f"feature:{feature}"
                            stats.skipped_reasons[reason] = stats.skipped_reasons.get(reason, 0) + 1

            if lolbin_got_rule:
                stats.lolbins_enriched += 1

        stats.log_summary(self.logger.info)
        return stats

    def _dry_run(
        self,
        rule_groups: list[etree._Element],
        generator: SysmonRuleGenerator,
    ) -> int:
        """
        Execute dry-run mode: print generated rules without saving.

        Args:
            rule_groups: List of generated RuleGroup XML elements.
            generator: SysmonRuleGenerator instance for XML conversion.

        Returns:
            Exit code 0 (always succeeds).
        """
        self.logger.info("Dry run mode - printing generated rules")

        sysmon_config = generator.create_sysmon_config(rule_groups)
        xml_str = generator.to_xml_string(sysmon_config)

        print("\n" + "=" * 60)
        print("GENERATED SYSMON RULES")
        print("=" * 60 + "\n")
        print(xml_str)

        total_rules = self._count_all_rules(rule_groups)
        self.logger.info(f"Generated {total_rules} rules in {len(rule_groups)} groups")
        return 0

    def _merge_with_existing(
        self,
        input_path: str,
        output_path: str,
        rule_groups: list[etree._Element],
        force: bool,
    ) -> int:
        """
        Merge generated rules with an existing Sysmon config.

        Args:
            input_path: Path to existing Sysmon XML config.
            output_path: Path to save merged config.
            rule_groups: List of generated RuleGroup XML elements.
            force: If True, replace existing duplicate rules.

        Returns:
            Exit code: 0 for success, 1 for errors.
        """
        try:
            config_manager = SysmonConfigManager(input_path)
            config_manager.load()
        except FileNotFoundError:
            self.logger.error(f"Input file not found: {input_path}")
            return 1
        except etree.XMLSyntaxError as e:
            self.logger.error(f"Invalid XML in input config: {e}")
            return 1

        try:
            added, skipped = config_manager.merge_rule_groups(rule_groups, force=force)
        except ValueError as e:
            self.logger.error(f"Failed to merge rules: {e}")
            return 1

        self.logger.info(f"Merge complete: {added} rules added, {skipped} skipped")

        try:
            config_manager.save(output_path)
        except OSError as e:
            self.logger.error(f"Failed to save config: {e}")
            return 1

        self.logger.info(f"Successfully saved merged config to {output_path}")
        return 0

    def _save_standalone(
        self,
        output_path: str,
        xml_element: etree._Element,
        generator: SysmonRuleGenerator,
    ) -> int:
        """
        Save generated rules as a standalone Sysmon config.

        Args:
            output_path: Path to save the XML file.
            xml_element: Root Sysmon XML element to save.
            generator: SysmonRuleGenerator instance for file writing.

        Returns:
            Exit code: 0 for success, 1 for errors.
        """
        try:
            generator.save_to_file(xml_element, output_path)
        except OSError as e:
            self.logger.error(f"Failed to save rules: {e}")
            return 1

        total_rules = self._count_all_rules_in_config(xml_element)
        self.logger.info(f"Successfully generated {total_rules} rules")
        return 0

    def _count_all_rules(self, rule_groups: list[etree._Element]) -> int:
        """
        Count total rules across all rule groups.

        Args:
            rule_groups: List of RuleGroup XML elements.

        Returns:
            Total number of rules (excluding comments).
        """
        total = 0
        for rg in rule_groups:
            for child in rg:
                if isinstance(child.tag, str):
                    total += len([c for c in child if isinstance(c.tag, str)])
        return total

    def _count_all_rules_in_config(self, element: etree._Element) -> int:
        """
        Count total rules in a complete Sysmon config element.

        Args:
            element: Root Sysmon XML element.

        Returns:
            Total number of rules across all RuleGroups.
        """
        total = 0
        for rg in element.iter("RuleGroup"):
            for child in rg:
                if isinstance(child.tag, str):
                    total += len([c for c in child if isinstance(c.tag, str)])
        return total

    @staticmethod
    def __is_counted_rule(elem_text: str, lolbas_names: set[str]) -> int:
        exec_name = elem_text.split("\\")[-1].lower()
        if ";" in exec_name:
            exec_names = exec_name.split(";")
            if any(x in lolbas_names for x in exec_names):
                return 1
        elif exec_name in lolbas_names:
            return 1
        return 0

    def _run_coverage_analysis(self, parsed_args) -> int:
        """
        Run LOLBAS coverage analysis on existing Sysmon config.

        Analyzes how many LOLBins from LOLBAS project are covered
        by rules in the specified Sysmon configuration file.

        Args:
            parsed_args: Parsed command-line arguments.

        Returns:
            Exit code: 0 for success, 1 for errors.
        """
        if not parsed_args.input:
            self.logger.error("Coverage analysis requires -i/--input with Sysmon config")
            return 1

        if not Path(parsed_args.input).exists():
            self.logger.error(f"Input file not found: {parsed_args.input}")
            return 1

        self.logger.info("Starting LOLBAS coverage analysis")

        config_loader = ConfigLoader()
        try:
            config = config_loader.load(parsed_args.config)
        except FileNotFoundError as e:
            self.logger.error(str(e))
            return 1

        try:
            client = LOLBASClient(url=config.lolbas.url, default_json=config.lolbas.json_file)
            raw_data = client.get_lolbas_data(
                parsed_args.lolbas_json,
                auto_update=config.lolbas.auto_update,
                max_age_days=config.lolbas.max_age_days,
            )
        except (FileNotFoundError, json.JSONDecodeError, httpx.HTTPError) as e:
            self.logger.error(f"Failed to load LOLBAS data: {e}")
            return 1

        lolbas_parser = LOLBASParser()
        lolbins = lolbas_parser.parse(raw_data)

        try:
            config_manager = SysmonConfigManager(parsed_args.input)
            config_manager.load()
        except etree.XMLSyntaxError as e:
            self.logger.error(f"Invalid XML in config: {e}")
            return 1

        config_executables = config_manager.get_all_executables_for_coverage()

        lolbas_names: set[str] = set()
        for lolbin in lolbins:
            lolbas_names.add(lolbin.name.lower())
            if lolbin.original_filename:
                lolbas_names.add(lolbin.original_filename.lower())

        cmd_rules = 0
        fallback_rules = 0

        for rule in config_manager.root.iter("Rule"):
            if rule.get("groupRelation") == "and":
                for tag in EXECUTABLE_TAGS:
                    elem = rule.find(tag)
                    if elem is not None and elem.text:
                        if self.__is_counted_rule(elem.text, lolbas_names):
                            cmd_rules += 1
                            break

        for tag in EXECUTABLE_TAGS:
            for elem in config_manager.root.iter(tag):
                parent = elem.getparent()
                if parent is not None and parent.tag != "Rule" and elem.text:
                    fallback_rules += self.__is_counted_rule(elem.text, lolbas_names)

        covered: list[str] = []
        missing: list[str] = []

        for lolbin in lolbins:
            name_lower = lolbin.name.lower()
            orig_lower = lolbin.original_filename.lower() if lolbin.original_filename else None

            is_covered = name_lower in config_executables or (orig_lower and orig_lower in config_executables)

            if is_covered:
                covered.append(lolbin.name)
            else:
                missing.append(lolbin.name)

        total = len(lolbins)
        coverage_pct = (len(covered) / total * 100) if total > 0 else 0

        print("LOLBAS Coverage Report\n")
        print(f"Total LOLBins in LOLBAS:    {total}")
        print(f"Covered in config:          {len(covered)}")
        print(f"Missing from config:        {len(missing)}")
        print(f"Coverage:                   {coverage_pct:.1f}%")
        print(f"CMD Rules:                  {cmd_rules}")
        print(f"Fallback rules:             {fallback_rules}")

        if parsed_args.show_covered and covered:
            print(f"\nCovered LOLBins ({len(covered)})")
            for name in sorted(covered):
                print(f"✓ {name}")

        if parsed_args.show_missing and missing:
            print(f"\nMissing LOLBins ({len(missing)})")
            for name in sorted(missing):
                print(f"✗ {name}")

        return 0
