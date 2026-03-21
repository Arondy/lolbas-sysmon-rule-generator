from pathlib import Path

from lolbas_sysmon.services.sigma_converter import SigmaConverter


def _write_sigma(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "rule.yml"
    path.write_text(body, encoding="utf-8")
    return path


def test_condition_selection_and_not_filter_parsed_to_branch(tmp_path: Path) -> None:
    rule_path = _write_sigma(
        tmp_path,
        """
title: Test Rule
id: 11111111-1111-1111-1111-111111111111
status: test
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\test.exe'
  filter:
    CommandLine|contains: '-safe'
  condition: selection and not filter
""",
    )

    converter = SigmaConverter()
    parsed = converter.parse_rule(rule_path)

    assert parsed is not None
    assert parsed.is_convertible()
    assert len(parsed.branches) == 1
    assert parsed.branches[0].include_blocks == ["selection"]
    assert parsed.branches[0].exclude_blocks == ["filter"]


def test_condition_one_of_them_is_marked_unsupported(tmp_path: Path) -> None:
    rule_path = _write_sigma(
        tmp_path,
        """
title: Unsupported Rule
id: 22222222-2222-2222-2222-222222222222
status: test
logsource:
  category: process_creation
  product: windows
detection:
  selection_a:
    Image|endswith: '\\a.exe'
  selection_b:
    Image|endswith: '\\b.exe'
  condition: 1 of them
""",
    )

    converter = SigmaConverter()
    parsed = converter.parse_rule(rule_path)

    assert parsed is not None
    assert not parsed.is_convertible()
    assert any("1 of them" in issue for issue in parsed.unsupported_features)
