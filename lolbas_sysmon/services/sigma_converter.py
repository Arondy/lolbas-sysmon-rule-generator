"""Sigma rule to Sysmon conversion helpers.

Parses Sigma YAML with pySigma (for metadata/logsource) and performs a focused,
safe conversion of detection blocks/conditions for Sysmon XML generation.

Supported condition logic (first iteration):
- selection_a and selection_b
- selection_a or selection_b
- 1 of selection_*
- all of selection_*
- selection_img and (all of selection_susp_* or selection_alt)
- selection and not filter  (converted with include + exclude branch metadata)

Unsupported features are recorded on the rule and must be skipped by generator.
"""

from __future__ import annotations

import fnmatch
import re
from pathlib import Path

import yaml
from sigma.rule import SigmaRule

from lolbas_sysmon.config import logger
from lolbas_sysmon.models import SigmaCondition, SigmaDetectionBlock, SigmaDetectionRule, SigmaRuleBranch

LOGSOURCE_MAP: dict[str, str] = {
    "process_creation": "ProcessCreate",
    "file_event": "FileCreate",
    "file_creation": "FileCreate",
    "file_access": "FileCreate",
    "network_connection": "NetworkConnect",
    "image_load": "ImageLoad",
    "process_access": "ProcessAccess",
    "registry_event": "RegistryEvent",
    "registry_set": "RegistryEvent",
    "registry_add": "RegistryEvent",
    "registry_delete": "RegistryEvent",
}

# Reverse mapping: Sysmon event type -> Sigma logsource category (primary)
SYSMON_TO_LOGSOURCE: dict[str, str] = {
    "ProcessCreate": "process_creation",
    "FileCreate": "file_event",
    "NetworkConnect": "network_connection",
    "ImageLoad": "image_load",
    "ProcessAccess": "process_access",
    "RegistryEvent": "registry_event",
}

FIELD_MAP: dict[str, str] = {
    "Image": "Image",
    "OriginalFileName": "OriginalFileName",
    "CommandLine": "CommandLine",
    "ParentImage": "ParentImage",
    "ParentCommandLine": "ParentCommandLine",
    "CurrentDirectory": "CurrentDirectory",
    "IntegrityLevel": "IntegrityLevel",
    "User": "User",
    "TargetFilename": "TargetFilename",
    "DestinationIp": "DestinationIp",
    "DestinationPort": "DestinationPort",
    "DestinationHostname": "DestinationHostname",
    "SourceIp": "SourceIp",
    "SourcePort": "SourcePort",
    "ImageLoaded": "ImageLoaded",
    "TargetObject": "TargetObject",
    "Details": "Details",
    "SourceImage": "SourceImage",
    "TargetImage": "TargetImage",
    # NetworkConnect (Event ID 3)
    "Initiated": "Initiated",
    # RegistryEvent (Event ID 12-14)
    "EventType": "EventType",
    # ProcessAccess (Event ID 10)
    "CallTrace": "CallTrace",
}

MODIFIER_MAP: dict[str, str] = {
    "": "is",
    "contains": "contains",
    "startswith": "begin with",
    "endswith": "end with",
    "contains|all": "contains all",
    "contains|any": "contains any",
}

UNSUPPORTED_MODIFIERS = {"re", "regex", "base64", "base64offset", "wide", "cidr"}
UNSUPPORTED_FEATURES = {"count", "near", "timeframe", "1 of them", "all of them"}


class SigmaConverter:
    def __init__(self) -> None:
        self.logger = logger.bind(class_name=self.__class__.__name__)

    def parse_rule(self, yaml_path: Path, source_url: str = "") -> SigmaDetectionRule | None:
        try:
            with open(yaml_path, "r", encoding="utf-8") as f:
                raw_content = f.read()
        except OSError as e:
            self.logger.warning(f"Failed to read Sigma file {yaml_path}: {e}")
            return None

        try:
            sigma_rule = SigmaRule.from_yaml(raw_content)
        except Exception as e:
            self.logger.warning(f"Failed to parse Sigma rule {yaml_path}: {e}")
            return None

        try:
            raw_yaml = yaml.safe_load(raw_content) or {}
        except yaml.YAMLError as e:
            self.logger.warning(f"Failed to decode YAML {yaml_path}: {e}")
            return None

        return self._convert_sigma_rule(sigma_rule, raw_yaml, source_url)

    def _convert_sigma_rule(self, sigma_rule: SigmaRule, raw_yaml: dict, source_url: str) -> SigmaDetectionRule | None:
        logsource_category = sigma_rule.logsource.category or ""
        if logsource_category not in LOGSOURCE_MAP:
            self.logger.debug(f"Skipping rule '{sigma_rule.title}': unsupported logsource category '{logsource_category}'")
            return None

        product = (sigma_rule.logsource.product or "").lower()
        if product and product != "windows":
            self.logger.debug(f"Skipping rule '{sigma_rule.title}': unsupported product '{product}'")
            return None

        detection_raw = raw_yaml.get("detection") or {}
        blocks, unsupported_fields, unsupported_features, block_aliases = self._parse_detection_blocks(detection_raw)
        condition_expr = str(detection_raw.get("condition", "")).strip()
        branches, condition_issues = self._parse_condition_to_branches(condition_expr, set(block_aliases.keys()))
        branches = self._expand_alias_branches(branches, block_aliases)
        unsupported_features.extend(condition_issues)
        unsupported_features = list(dict.fromkeys(unsupported_features))

        rule = SigmaDetectionRule(
            title=sigma_rule.title or "Unknown",
            rule_id=str(sigma_rule.id) if sigma_rule.id else "",
            level=str(sigma_rule.level) if sigma_rule.level else "medium",
            logsource_category=logsource_category,
            mitre_tags=self._extract_mitre_tags([str(t) for t in (sigma_rule.tags or [])]),
            detection_blocks=list(blocks.values()),
            condition_expr=condition_expr,
            unsupported_fields=unsupported_fields,
            unsupported_features=unsupported_features,
            branches=branches,
            source_url=source_url,
        )

        if rule.unsupported_fields or rule.unsupported_features:
            self.logger.debug(f"Skipping Sigma rule '{rule.title}': unsupported fields={rule.unsupported_fields}, features={rule.unsupported_features}")

        return rule

    def _parse_detection_blocks(
        self,
        detection_raw: dict,
    ) -> tuple[dict[str, SigmaDetectionBlock], list[str], list[str], dict[str, list[str]]]:
        blocks: dict[str, SigmaDetectionBlock] = {}
        unsupported_fields: list[str] = []
        unsupported_features: list[str] = []
        block_aliases: dict[str, list[str]] = {}

        for key, value in detection_raw.items():
            if key == "condition":
                continue

            # In Sigma, a list of maps under one block means OR between items.
            # We model this by creating virtual sub-blocks and later expanding
            # condition branches through alias cartesian expansion.
            if isinstance(value, list):
                expanded_names: list[str] = []
                for idx, item in enumerate(value):
                    conds = self._extract_conditions(item, unsupported_fields, unsupported_features)
                    if not conds:
                        continue
                    sub_name = f"{key}_{idx}"
                    blocks[sub_name] = SigmaDetectionBlock(name=sub_name, conditions=conds)
                    expanded_names.append(sub_name)
                if expanded_names:
                    block_aliases[key] = expanded_names
                continue

            conds = self._extract_conditions(value, unsupported_fields, unsupported_features)
            if conds:
                blocks[key] = SigmaDetectionBlock(name=key, conditions=conds)
                block_aliases[key] = [key]

        return blocks, list(dict.fromkeys(unsupported_fields)), list(dict.fromkeys(unsupported_features)), block_aliases

    def _expand_alias_branches(
        self,
        branches: list[SigmaRuleBranch],
        block_aliases: dict[str, list[str]],
    ) -> list[SigmaRuleBranch]:
        """Expand alias block names to concrete virtual blocks.

        Example:
          selection_img -> [selection_img_0, selection_img_1]
        A branch with include [selection_img, selection_cli] becomes two branches:
          [selection_img_0, selection_cli]
          [selection_img_1, selection_cli]
        """
        expanded: list[SigmaRuleBranch] = []

        for branch in branches:
            variants: list[SigmaRuleBranch] = [SigmaRuleBranch(include_blocks=[], exclude_blocks=[])]

            for alias in branch.include_blocks:
                options = block_aliases.get(alias, [alias])
                next_variants: list[SigmaRuleBranch] = []
                for v in variants:
                    for opt in options:
                        next_variants.append(
                            SigmaRuleBranch(
                                include_blocks=v.include_blocks + [opt],
                                exclude_blocks=v.exclude_blocks,
                            )
                        )
                variants = next_variants

            for alias in branch.exclude_blocks:
                options = block_aliases.get(alias, [alias])
                next_variants = []
                for v in variants:
                    for opt in options:
                        next_variants.append(
                            SigmaRuleBranch(
                                include_blocks=v.include_blocks,
                                exclude_blocks=v.exclude_blocks + [opt],
                            )
                        )
                variants = next_variants

            expanded.extend(variants)

        # Normalize and deduplicate
        out: list[SigmaRuleBranch] = []
        seen: set[tuple[tuple[str, ...], tuple[str, ...]]] = set()
        for b in expanded:
            inc = tuple(dict.fromkeys(b.include_blocks))
            exc = tuple(dict.fromkeys(b.exclude_blocks))
            key = (inc, exc)
            if key in seen:
                continue
            seen.add(key)
            out.append(SigmaRuleBranch(include_blocks=list(inc), exclude_blocks=list(exc)))
        return out

    def _extract_conditions(self, node, unsupported_fields: list[str], unsupported_features: list[str]) -> list[SigmaCondition]:
        conditions: list[SigmaCondition] = []

        if isinstance(node, dict):
            for raw_key, raw_value in node.items():
                if "|" in raw_key:
                    field, *mods = raw_key.split("|")
                else:
                    field, mods = raw_key, []

                mapped = FIELD_MAP.get(field)
                if not mapped:
                    if field not in unsupported_fields:
                        unsupported_fields.append(field)
                    continue

                modifier, modifier_issue = self._map_modifiers(mods)
                if modifier_issue:
                    if modifier_issue not in unsupported_features:
                        unsupported_features.append(modifier_issue)
                    continue

                values = self._to_values(raw_value)
                if not values:
                    continue

                # If Sigma lists multiple values with a simple "contains" modifier,
                # interpret it as "contains any" to preserve the OR semantics.
                if modifier == "contains" and len(values) > 1:
                    modifier = "contains any"

                conditions.append(SigmaCondition(field=mapped, modifier=modifier, values=values))

        elif isinstance(node, list):
            for item in node:
                # List handling at block-level is performed in _parse_detection_blocks.
                # Here we only flatten nested scalar lists that belong to a field value.
                conditions.extend(self._extract_conditions(item, unsupported_fields, unsupported_features))

        return conditions

    def _map_modifiers(self, mods: list[str]) -> tuple[str, str | None]:
        lowered = [m.lower() for m in mods]
        for mod in lowered:
            if mod in UNSUPPORTED_MODIFIERS:
                return "", mod

        if "contains" in lowered and "all" in lowered:
            key = "contains|all"
        elif "contains" in lowered and "any" in lowered:
            key = "contains|any"
        elif "contains" in lowered:
            key = "contains"
        elif "startswith" in lowered:
            key = "startswith"
        elif "endswith" in lowered:
            key = "endswith"
        elif not lowered:
            key = ""
        else:
            # Unsupported but explicit modifier combo
            return "", "|".join(lowered)

        return MODIFIER_MAP[key], None

    def _to_values(self, value) -> list[str]:
        if isinstance(value, list):
            out: list[str] = []
            for v in value:
                out.extend(self._to_values(v))
            return out
        if isinstance(value, (str, int, float)):
            return [str(value)]
        return []

    def _extract_mitre_tags(self, tags: list[str]) -> list[str]:
        pattern = re.compile(r"t\d{4}(?:\.\d{3})?", re.IGNORECASE)
        out: list[str] = []
        for tag in tags:
            if "attack." not in tag.lower():
                continue
            m = pattern.search(tag)
            if m:
                out.append(m.group().upper())
        return list(dict.fromkeys(out))

    def _parse_condition_to_branches(
        self,
        condition_expr: str,
        available_blocks: set[str],
    ) -> tuple[list[SigmaRuleBranch], list[str]]:
        issues: list[str] = []
        if not condition_expr:
            # Default fallback: OR all blocks
            return [SigmaRuleBranch(include_blocks=[b]) for b in sorted(available_blocks)], issues

        tokens = self._tokenize(condition_expr)
        token_l = [t.lower() for t in tokens]
        if "count" in token_l:
            issues.append("count")
        if "near" in token_l:
            issues.append("near")
        if "timeframe" in token_l:
            issues.append("timeframe")

        try:
            parser = _ConditionParser(tokens, available_blocks)
            branches = parser.parse()
            issues.extend(parser.issues)
            # normalize & dedup
            normalized: list[SigmaRuleBranch] = []
            seen: set[tuple[tuple[str, ...], tuple[str, ...]]] = set()
            for b in branches:
                inc = tuple(sorted(dict.fromkeys(b.include_blocks)))
                exc = tuple(sorted(dict.fromkeys(b.exclude_blocks)))
                key = (inc, exc)
                if key in seen:
                    continue
                seen.add(key)
                normalized.append(SigmaRuleBranch(include_blocks=list(inc), exclude_blocks=list(exc)))
            if not normalized:
                issues.append("empty_condition")
            return normalized, list(dict.fromkeys(issues))
        except Exception:
            issues.append("complex_condition")
            return [], list(dict.fromkeys(issues))

    def _tokenize(self, expr: str) -> list[str]:
        pattern = re.compile(r"\(|\)|\band\b|\bor\b|\bnot\b|\bof\b|\b1\b|\ball\b|[A-Za-z0-9_*.-]+", re.IGNORECASE)
        return [t for t in pattern.findall(expr) if t.strip()]

    def get_sysmon_event_type(self, logsource_category: str) -> str | None:
        return LOGSOURCE_MAP.get(logsource_category)

    def is_rule_convertible(self, rule: SigmaDetectionRule) -> bool:
        return rule.is_convertible() and len(rule.branches) > 0


class _ConditionParser:
    """Tiny parser for a limited Sigma condition subset (stage 1)."""

    def __init__(self, tokens: list[str], available_blocks: set[str]) -> None:
        self.tokens = tokens
        self.pos = 0
        self.available = available_blocks
        self.issues: list[str] = []

    def parse(self) -> list[SigmaRuleBranch]:
        branches = self._parse_or()
        if self.pos != len(self.tokens):
            self.issues.append("complex_condition")
        return branches

    def _peek(self) -> str | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _consume(self, expected: str | None = None) -> str | None:
        tok = self._peek()
        if tok is None:
            return None
        if expected is not None and tok.lower() != expected:
            return None
        self.pos += 1
        return tok

    def _parse_or(self) -> list[SigmaRuleBranch]:
        left = self._parse_and()
        while (self._peek() or "").lower() == "or":
            self._consume("or")
            right = self._parse_and()
            left = left + right
        return left

    def _parse_and(self) -> list[SigmaRuleBranch]:
        left = self._parse_not_term()
        while (self._peek() or "").lower() == "and":
            self._consume("and")
            right = self._parse_not_term()
            combined: list[SigmaRuleBranch] = []
            for _l in left:
                for _r in right:
                    combined.append(
                        SigmaRuleBranch(
                            include_blocks=_l.include_blocks + _r.include_blocks,
                            exclude_blocks=_l.exclude_blocks + _r.exclude_blocks,
                        )
                    )
            left = combined
        return left

    def _parse_not_term(self) -> list[SigmaRuleBranch]:
        if (self._peek() or "").lower() == "not":
            self._consume("not")
            prim = self._parse_primary()
            # Support only simple NOT over primitive branches (single include block each)
            negated: list[SigmaRuleBranch] = []
            for p in prim:
                if p.exclude_blocks or len(p.include_blocks) != 1:
                    self.issues.append("not")
                    return []
                negated.append(SigmaRuleBranch(include_blocks=[], exclude_blocks=[p.include_blocks[0]]))
            return negated
        return self._parse_primary()

    def _parse_primary(self) -> list[SigmaRuleBranch]:
        tok = self._peek()
        if tok is None:
            return []
        if tok == "(":
            self._consume("(")
            inner = self._parse_or()
            if self._peek() == ")":
                self._consume(")")
            else:
                self.issues.append("complex_condition")
            return inner

        # 1 of <pattern> / all of <pattern>
        if tok.lower() in {"1", "all"}:
            quant = tok.lower()
            self._consume()
            if (self._peek() or "").lower() != "of":
                self.issues.append("complex_condition")
                return []
            self._consume("of")
            pattern = self._consume()
            if not pattern:
                self.issues.append("complex_condition")
                return []
            pattern_l = pattern.lower()
            if pattern_l == "them":
                self.issues.append(f"{quant} of them")
                return []
            matches = sorted([b for b in self.available if fnmatch.fnmatch(b.lower(), pattern_l)])
            if not matches:
                self.issues.append("complex_condition")
                return []
            if quant == "all":
                return [SigmaRuleBranch(include_blocks=matches)]
            return [SigmaRuleBranch(include_blocks=[m]) for m in matches]

        # named block
        name = self._consume()
        if name in self.available:
            return [SigmaRuleBranch(include_blocks=[name])]

        # Unknown identifier in condition
        self.issues.append("complex_condition")
        return []
