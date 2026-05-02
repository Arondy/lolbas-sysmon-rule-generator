import subprocess

from .models import ProcessResult


def run_powershell(script: str, timeout_seconds: int) -> ProcessResult:
    cmd = [
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        script,
    ]
    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout_seconds,
        )
        return ProcessResult(
            exit_code=completed.returncode,
            stdout=completed.stdout or "",
            stderr=completed.stderr or "",
        )
    except subprocess.TimeoutExpired as e:
        return ProcessResult(
            exit_code=-1,
            stdout=e.stdout or "",
            stderr=f"Process timed out after {timeout_seconds} seconds. {e.stderr or ''}",
        )


def run_cmd_marker(marker_token: str, timeout_seconds: int) -> ProcessResult:
    cmd = ["cmd.exe", "/d", "/s", "/c", f"echo {marker_token}>nul"]
    completed = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        errors="replace",
        timeout=timeout_seconds,
    )
    return ProcessResult(
        exit_code=completed.returncode,
        stdout=completed.stdout or "",
        stderr=completed.stderr or "",
    )


def invoke_atomic_test(
    technique_id: str,
    test_number: int,
    atomics_path: str,
    timeout_seconds: int,
    cleanup: bool,
) -> ProcessResult:
    cleanup_flag = " -Cleanup" if cleanup else ""
    escaped_technique = technique_id.replace("'", "''")
    escaped_path = atomics_path.replace("'", "''")
    script = (
        "$ErrorActionPreference='Stop'; "
        "Import-Module Invoke-AtomicRedTeam -Force; "
        f"Invoke-AtomicTest -AtomicTechnique '{escaped_technique}' "
        f"-TestNumbers '{test_number}' "
        f"-PathToAtomicsFolder '{escaped_path}' "
        f"-TimeoutSeconds {timeout_seconds}"
        f"{cleanup_flag}"
    )
    return run_powershell(script, timeout_seconds + 60)
