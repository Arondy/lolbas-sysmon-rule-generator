import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from lolbas_sysmon.config import logger

DEFAULT_OUTPUT_FILE = "lolbas_rules.xml"
DEFAULT_CONFIG_PATH = "config.toml"


@dataclass
class LolbasConfig:
    json_file: str = "lolbas.json"
    url: str = "https://lolbas-project.github.io/api/lolbas.json"


@dataclass
class MitreConfig:
    json_file: str = "enterprise-attack.json"
    url: str = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"


@dataclass
class Config:
    categories: list[str] = field(default_factory=list)
    mappings: dict[str, list[str]] = field(default_factory=dict)
    event_conditions: dict[str, list[str]] = field(default_factory=dict)
    rule_group_prefix: str = "LOLBAS_"
    rule_group_cmd_prefix: str = "LOLBAS_CMD_"
    unique_rules: bool = False
    lolbas: LolbasConfig = field(default_factory=LolbasConfig)
    mitre: MitreConfig = field(default_factory=MitreConfig)

    def get_event_types(self, category: str) -> list[str]:
        """Get all event types for a category."""
        return self.mappings.get(category, ["ProcessCreate"])

    def get_rule_group_name(self, category: str, with_cmdline: bool = False) -> str:
        prefix = self.rule_group_cmd_prefix if with_cmdline else self.rule_group_prefix
        return f"{prefix}{category}".replace(" ", "_")

    def get_condition_tags(self, event_type: str) -> tuple[str, str | None]:
        tags = self.event_conditions.get(event_type, ["Image"])
        preferred = tags[0]
        fallback = tags[1] if len(tags) > 1 else None
        return (preferred, fallback)


class ConfigLoader:
    def __init__(self) -> None:
        self.logger = logger.bind(class_name=self.__class__.__name__)

    def load(self, config_path: str | None = None) -> Config:
        path_str = config_path or DEFAULT_CONFIG_PATH
        path = Path(path_str)

        if not path.exists():
            self.logger.error(f"Config file not found: {path_str}")
            raise FileNotFoundError(f"Config file not found: {path_str}")

        self.logger.info(f"Loading configuration from {path_str}")

        with open(path, "rb") as f:
            data = tomllib.load(f)

        return self._parse_config(data)

    def _parse_config(self, data: dict) -> Config:
        config = Config()

        if "categories" in data and "enabled" in data["categories"]:
            config.categories = data["categories"]["enabled"]

        if "mappings" in data:
            config.mappings.update(data["mappings"])

        if "event_conditions" in data:
            config.event_conditions.update(data["event_conditions"])

        if "rule_groups" in data:
            rg = data["rule_groups"]
            if "prefix" in rg:
                config.rule_group_prefix = rg["prefix"]
            if "cmd_prefix" in rg:
                config.rule_group_cmd_prefix = rg["cmd_prefix"]
            if "unique_rules" in rg:
                config.unique_rules = rg["unique_rules"]

        if "lolbas" in data:
            lolbas_data = data["lolbas"]
            config.lolbas = LolbasConfig(
                json_file=lolbas_data.get("json_file", "lolbas.json"),
                url=lolbas_data.get("url", "https://lolbas-project.github.io/api/lolbas.json"),
            )

        if "mitre" in data:
            mitre_data = data["mitre"]
            config.mitre = MitreConfig(
                json_file=mitre_data.get("json_file", "enterprise-attack.json"),
                url=mitre_data.get("url", "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"),
            )

        return config
