from lolbas_sysmon.config.settings import Config
from lolbas_sysmon.models import LOLBin, SigmaCondition, SigmaDetectionBlock, SigmaDetectionRule, SigmaRuleBranch
from lolbas_sysmon.services.rule_generator import SysmonRuleGenerator


def test_generate_sigma_include_and_exclude_rules() -> None:
    config = Config(
        mappings={"Execute": ["ProcessCreate"]},
        event_conditions={"ProcessCreate": ["Image"]},
    )
    generator = SysmonRuleGenerator(config)

    sigma_rule = SigmaDetectionRule(
        title="Sigma A and not B",
        rule_id="rid",
        level="high",
        logsource_category="process_creation",
        detection_blocks=[
            SigmaDetectionBlock(
                name="selection",
                conditions=[
                    SigmaCondition(field="Image", modifier="end with", values=["\\test.exe"]),
                ],
            ),
            SigmaDetectionBlock(
                name="filter",
                conditions=[
                    SigmaCondition(field="CommandLine", modifier="contains", values=["-safe"]),
                ],
            ),
        ],
        condition_expr="selection and not filter",
        branches=[
            SigmaRuleBranch(include_blocks=["selection"], exclude_blocks=["filter"]),
        ],
    )

    lolbin = LOLBin(
        name="test.exe",
        original_filename=None,
        description="",
        sigma_rules=[sigma_rule],
    )

    include_rules, exclude_rules, used_sigma_rules = generator._generate_cmdline_rules(lolbin, "Execute", "ProcessCreate")

    assert len(include_rules) == 1
    assert len(exclude_rules) == 1
    assert len(used_sigma_rules) == 1

    include_xml = generator.to_xml_string(include_rules[0], pretty=False)
    exclude_xml = generator.to_xml_string(exclude_rules[0], pretty=False)

    assert "<Image condition=\"end with\">\\test.exe</Image>" in include_xml
    assert "CommandLine" not in include_xml
    assert "<Image condition=\"end with\">\\test.exe</Image>" in exclude_xml
    assert "<CommandLine condition=\"contains\">-safe</CommandLine>" in exclude_xml
