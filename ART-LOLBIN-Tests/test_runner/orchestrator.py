import json
import platform
import re
import time
import uuid
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from .models import AppConfig, CaseResult, MarkerEvent, RunResult, TestCase
from .process_runner import invoke_atomic_test, run_cmd_marker
from .sysmon_client import find_marker_event, get_window_events

MITRE_TECHNIQUE_RE = re.compile(r"T\d{4}(?:\.\d{3})?", re.IGNORECASE)
LOLBAS_CMD_PREFIX_RE = re.compile(r"^\s*LOLBAS_CMD(?:\b|[/\\:_-])", re.IGNORECASE)
LOLBAS_ANY_RE = re.compile(r"\bLOLBAS\b", re.IGNORECASE)


def extract_technique_from_rule(rule_name: str) -> str | None:
    match = MITRE_TECHNIQUE_RE.search(rule_name)
    if match:
        return match.group(0).upper()
    return None


def compare_techniques(test_technique: str, rule_technique: str) -> str | None:
    test_technique = test_technique.upper()
    rule_technique = rule_technique.upper()

    test_parts = test_technique.split('.')
    rule_parts = rule_technique.split('.')

    test_base = test_parts[0]
    rule_base = rule_parts[0]

    if test_base != rule_base:
        return None

    test_has_sub = len(test_parts) > 1
    rule_has_sub = len(rule_parts) > 1

    if not test_has_sub and rule_has_sub:
        return "precise"

    if test_technique == rule_technique:
        return "precise"

    return "regular"


def run_benchmark(config: AppConfig, save_mode: bool = False) -> RunResult:
    started = utc_now_iso()
    run_id = build_run_id()

    existing_results: list[CaseResult] = []
    completed_case_ids: set[str] = set()

    if save_mode:
        existing_results, completed_case_ids = load_existing_results(config.output_json_path)
        if existing_results:
            print(f"Загружено {len(existing_results)} существующих результатов")

    tests_to_run = [case for case in config.tests if case.case_id not in completed_case_ids]

    print(f"Старт прогона: {run_id}")
    print(f"Канал Sysmon: {config.sysmon_channel}")
    print(f"Путь к atomics: {config.atomics_path}")
    print(f"Количество кейсов к выполнению: {len(tests_to_run)} (всего в конфиге: {len(config.tests)})")

    if save_mode and not tests_to_run:
        print("Все тесты уже выполнены, выход")
        ended = utc_now_iso()
        summary = build_summary(existing_results)
        run_result = RunResult(
            run_id=run_id,
            host=platform.node(),
            sysmon_channel=config.sysmon_channel,
            atomics_path=config.atomics_path,
            started_utc=started,
            ended_utc=ended,
            summary=summary,
            cases=existing_results,
        )
        return run_result

    all_results = list(existing_results)

    for index, case in enumerate(tests_to_run, start=1):
        print(f"\n[{index}/{len(tests_to_run)}] {case.case_id}")
        case_result = execute_case(case=case, config=config, run_id=run_id)
        all_results.append(case_result)

        if save_mode:
            save_intermediate_result(all_results, config, run_id, started)

    ended = utc_now_iso()
    summary = build_summary(all_results)

    run_result = RunResult(
        run_id=run_id,
        host=platform.node(),
        sysmon_channel=config.sysmon_channel,
        atomics_path=config.atomics_path,
        started_utc=started,
        ended_utc=ended,
        summary=summary,
        cases=all_results,
    )

    if not save_mode:
        save_run_result(run_result, config.output_json_path)
        print(f"\nГотово. Результат сохранен: {config.output_json_path}")
    else:
        print(f"\nГотово. Всего выполнено тестов: {len(all_results)}")

    return run_result


def execute_case(case: TestCase, config: AppConfig, run_id: str) -> CaseResult:
    status = "ok"
    error = ""
    start_marker: MarkerEvent | None = None
    end_marker: MarkerEvent | None = None
    upper_marker: MarkerEvent | None = None
    atomic_exit_code: int | None = None
    cleanup_exit_code: int | None = None
    sysmon_events_count = 0
    tp = 0
    tp_precise = 0
    tp_regular = 0
    fn = 0
    matched_rule_names: list[str] = []

    try:
        start_token = build_marker_token(run_id, case.case_id, "START")
        emit_marker_or_fail(start_token, config.marker_timeout_seconds)
        start_marker = wait_marker_or_fail(start_token, config)

        atomic_result = invoke_atomic_test(
            technique_id=case.technique_id,
            test_number=case.test_number,
            atomics_path=config.atomics_path,
            timeout_seconds=config.atomic_timeout_seconds,
            cleanup=False,
        )
        atomic_exit_code = atomic_result.exit_code
        if atomic_result.exit_code != 0:
            status = "atomic_error"
            error = short_text(atomic_result.stderr or atomic_result.stdout)

        if config.run_cleanup:
            cleanup_result = invoke_atomic_test(
                technique_id=case.technique_id,
                test_number=case.test_number,
                atomics_path=config.atomics_path,
                timeout_seconds=config.atomic_timeout_seconds,
                cleanup=True,
            )
            cleanup_exit_code = cleanup_result.exit_code
            if cleanup_result.exit_code != 0 and status == "ok":
                status = "cleanup_error"
                error = short_text(cleanup_result.stderr or cleanup_result.stdout)

        end_token = build_marker_token(run_id, case.case_id, "END")
        emit_marker_or_fail(end_token, config.marker_timeout_seconds)
        end_marker = wait_marker_or_fail(end_token, config)

        if config.grace_seconds > 0:
            time.sleep(config.grace_seconds)

        upper_token = build_marker_token(run_id, case.case_id, "UPPER")
        emit_marker_or_fail(upper_token, config.marker_timeout_seconds)
        upper_marker = wait_marker_or_fail(upper_token, config)

        window_start = start_marker.record_id
        window_end = upper_marker.record_id
        events = get_window_events(
            channel=config.sysmon_channel,
            start_record_id=window_start,
            end_record_id=window_end,
            batch_size=config.query_batch_size,
        )
        non_marker_events = [e for e in events if not is_marker_event(e.command_line)]
        sysmon_events_count = len(non_marker_events)

        precise_rule_names, regular_rule_names = find_matching_rule_names(non_marker_events, case.technique_id)
        if precise_rule_names:
            tp = 1
            tp_precise = 1
            tp_regular = 0
            fn = 0
            matched_rule_names = precise_rule_names
        elif regular_rule_names:
            tp = 1
            tp_precise = 0
            tp_regular = 1
            fn = 0
            matched_rule_names = regular_rule_names
        else:
            tp = 0
            tp_precise = 0
            tp_regular = 0
            fn = 1

        print(f"    Событий Sysmon в окне: {sysmon_events_count}, TP={tp}, TP_precise={tp_precise}, TP_regular={tp_regular}, FN={fn}")
        if matched_rule_names:
            print(f"    RuleName (match): {', '.join(matched_rule_names)}")

    except Exception as exc:
        status = "error"
        error = short_text(str(exc))
        print(f"    [!] Ошибка кейса: {error}")

    return CaseResult(
        case_id=case.case_id,
        technique_id=case.technique_id,
        test_number=case.test_number,
        status=status,
        error=error,
        window_start_record_id=start_marker.record_id if start_marker else None,
        window_end_record_id=upper_marker.record_id if upper_marker else (end_marker.record_id if end_marker else None),
        window_start_time_utc=start_marker.system_time_utc if start_marker else None,
        window_end_time_utc=upper_marker.system_time_utc if upper_marker else (end_marker.system_time_utc if end_marker else None),
        atomic_exit_code=atomic_exit_code,
        cleanup_exit_code=cleanup_exit_code,
        sysmon_events_count=sysmon_events_count,
        tp=tp,
        tp_precise=tp_precise,
        tp_regular=tp_regular,
        fn=fn,
        matched_rule_names=matched_rule_names,
    )


def emit_marker_or_fail(marker_token: str, timeout_seconds: int) -> None:
    result = run_cmd_marker(marker_token, timeout_seconds)
    if result.exit_code != 0:
        text = short_text(result.stderr or result.stdout)
        raise RuntimeError(f"Не удалось поставить маркер {marker_token}: {text}")


def wait_marker_or_fail(marker_token: str, config: AppConfig) -> MarkerEvent:
    marker = find_marker_event(
        channel=config.sysmon_channel,
        marker_token=marker_token,
        timeout_seconds=config.marker_timeout_seconds,
        poll_interval_seconds=config.marker_poll_interval_seconds,
        scan_limit=config.marker_scan_limit,
        batch_size=config.query_batch_size,
    )
    if marker is None:
        raise RuntimeError(f"Маркер не найден в Sysmon: {marker_token}")
    return marker


def is_marker_event(command_line: str) -> bool:
    return "ARTM_" in command_line


def find_matching_rule_names(
    events: list[MarkerEvent],
    test_technique_id: str,
) -> tuple[list[str], list[str]]:
    precise_matches: list[str] = []
    regular_matches: list[str] = []

    for event in events:
        rule_name = (event.rule_name or "").strip()
        if not rule_name:
            continue

        match_type = classify_rule_name(rule_name, test_technique_id)
        if match_type == "precise" and rule_name not in precise_matches:
            precise_matches.append(rule_name)
        elif match_type == "regular" and rule_name not in regular_matches:
            regular_matches.append(rule_name)

    return precise_matches, regular_matches


def classify_rule_name(rule_name: str, test_technique_id: str) -> str | None:
    rule_technique = extract_technique_from_rule(rule_name)

    if not rule_technique:
        return None

    return compare_techniques(test_technique_id, rule_technique)


def build_marker_token(run_id: str, case_id: str, phase: str) -> str:
    run_part = sanitize_token_part(run_id)
    case_part = sanitize_token_part(case_id)
    unique_part = uuid.uuid4().hex[:12]
    return f"ARTM_{phase}_{run_part}_{case_part}_{unique_part}"


def sanitize_token_part(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_-]", "_", value)


def build_run_id() -> str:
    now = datetime.now(timezone.utc)
    return now.strftime("%Y%m%dT%H%M%SZ")


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def short_text(value: str) -> str:
    text = (value or "").strip().replace("\r", " ").replace("\n", " ")
    return text[:500]


def build_summary(case_results: list[CaseResult]) -> dict:
    cases_total = len(case_results)
    completed_cases = [x for x in case_results if x.status != "error"]
    tp = sum(x.tp for x in case_results)
    tp_precise = sum(x.tp_precise for x in case_results)
    tp_regular = sum(x.tp_regular for x in case_results)
    fn = sum(x.fn for x in case_results)
    recall = None
    if tp + fn > 0:
        recall = round(tp / (tp + fn), 6)

    summary = {
        "cases_total": cases_total,
        "cases_completed": len(completed_cases),
        "cases_error": cases_total - len(completed_cases),
        "tp": tp,
        "tp_precise": tp_precise,
        "tp_regular": tp_regular,
        "fn": fn,
        "fp": None,
        "precision": None,
        "recall": recall,
    }
    return summary


def save_run_result(run_result: RunResult, output_path: str) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "run_id": run_result.run_id,
        "host": run_result.host,
        "sysmon_channel": run_result.sysmon_channel,
        "atomics_path": run_result.atomics_path,
        "started_utc": run_result.started_utc,
        "ended_utc": run_result.ended_utc,
        "summary": run_result.summary,
        "cases": [asdict(x) for x in run_result.cases],
    }
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def load_existing_results(output_path: str) -> tuple[list[CaseResult], set[str]]:
    path = Path(output_path)
    if not path.exists():
        return [], set()

    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)

        cases_data = data.get("cases", [])
        existing_results = []
        completed_case_ids = set()

        for case_data in cases_data:
            case_result = CaseResult(**case_data)
            existing_results.append(case_result)
            completed_case_ids.add(case_result.case_id)

        return existing_results, completed_case_ids
    except Exception as exc:
        print(f"[!] Ошибка загрузки существующих результатов: {exc}")
        return [], set()


def save_intermediate_result(all_results: list[CaseResult], config: AppConfig, run_id: str, started: str) -> None:
    ended = utc_now_iso()
    summary = build_summary(all_results)

    run_result = RunResult(
        run_id=run_id,
        host=platform.node(),
        sysmon_channel=config.sysmon_channel,
        atomics_path=config.atomics_path,
        started_utc=started,
        ended_utc=ended,
        summary=summary,
        cases=all_results,
    )
    save_run_result(run_result, config.output_json_path)
