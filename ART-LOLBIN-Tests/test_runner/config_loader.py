import json
from pathlib import Path

from .models import AppConfig, TestCase


def load_config(config_path: str, output_override: str | None = None) -> AppConfig:
    path = Path(config_path)
    if not path.exists():
        raise RuntimeError(f"Файл конфигурации не найден: {path}")

    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    tests = expand_tests(data.get("tests", []))
    if not tests:
        raise RuntimeError("В конфигурации нет тестов в секции tests")

    atomics_path = data.get("atomics_path", "").strip()
    if not atomics_path:
        raise RuntimeError("В конфигурации не задан atomics_path")

    output_json_path = output_override or data.get("output_json_path", "").strip()
    if not output_json_path:
        raise RuntimeError("В конфигурации не задан output_json_path")

    cfg = AppConfig(
        atomics_path=atomics_path,
        output_json_path=output_json_path,
        marker_timeout_seconds=int(data.get("marker_timeout_seconds", 20)),
        marker_poll_interval_seconds=float(data.get("marker_poll_interval_seconds", 0.5)),
        marker_scan_limit=int(data.get("marker_scan_limit", 300)),
        query_batch_size=int(data.get("query_batch_size", 128)),
        grace_seconds=int(data.get("grace_seconds", 0)),
        atomic_timeout_seconds=int(data.get("atomic_timeout_seconds", 900)),
        run_cleanup=bool(data.get("run_cleanup", True)),
        sysmon_channel=str(data.get("sysmon_channel", "Microsoft-Windows-Sysmon/Operational")),
        tests=tests,
    )
    return cfg


def expand_tests(raw_tests: list[dict]) -> list[TestCase]:
    cases: list[TestCase] = []
    for item in raw_tests:
        technique_id = str(item.get("technique_id", "")).strip()
        if not technique_id:
            raise RuntimeError("В tests обнаружен элемент без technique_id")

        numbers = resolve_test_numbers(item)
        for test_number in numbers:
            if test_number < 1:
                raise RuntimeError(f"Недопустимый test_number для {technique_id}: {test_number}")
            case_id = f"{technique_id}#{test_number}"
            cases.append(
                TestCase(
                    technique_id=technique_id,
                    test_number=test_number,
                    case_id=case_id,
                )
            )
    return cases


def resolve_test_numbers(item: dict) -> list[int]:
    if "test_number" in item:
        return [int(item["test_number"])]

    if "test_numbers" in item:
        values = item["test_numbers"]
        if not isinstance(values, list) or not values:
            raise RuntimeError("test_numbers должен быть непустым списком")
        return [int(x) for x in values]

    raise RuntimeError("Для теста должен быть указан test_number или test_numbers")
