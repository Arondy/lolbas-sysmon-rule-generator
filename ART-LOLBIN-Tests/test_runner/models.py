from dataclasses import asdict, dataclass, field


@dataclass
class TestCase:
    technique_id: str
    test_number: int
    case_id: str


@dataclass
class MarkerEvent:
    record_id: int
    event_id: int
    system_time_utc: str
    rule_name: str
    command_line: str


@dataclass
class ProcessResult:
    exit_code: int
    stdout: str
    stderr: str


@dataclass
class CaseResult:
    case_id: str
    technique_id: str
    test_number: int
    status: str
    error: str
    window_start_record_id: int | None
    window_end_record_id: int | None
    window_start_time_utc: str | None
    window_end_time_utc: str | None
    atomic_exit_code: int | None
    cleanup_exit_code: int | None
    sysmon_events_count: int
    tp: int
    tp_precise: int
    tp_regular: int
    fn: int
    matched_rule_names: list[str]


@dataclass
class AppConfig:
    atomics_path: str
    output_json_path: str
    marker_timeout_seconds: int
    marker_poll_interval_seconds: float
    marker_scan_limit: int
    query_batch_size: int
    grace_seconds: int
    atomic_timeout_seconds: int
    run_cleanup: bool
    sysmon_channel: str
    tests: list[TestCase] = field(default_factory=list)


@dataclass
class RunResult:
    run_id: str
    host: str
    sysmon_channel: str
    atomics_path: str
    started_utc: str
    ended_utc: str
    summary: dict
    cases: list[CaseResult]

    def to_dict(self) -> dict:
        return asdict(self)
