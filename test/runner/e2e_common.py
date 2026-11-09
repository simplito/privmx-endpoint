from __future__ import annotations

import datetime
import os
import shlex
import subprocess
import threading
from pathlib import Path
from typing import Sequence

SCRIPT_DIR = Path(__file__).resolve().parent
TEST_DIR = SCRIPT_DIR.parent
REPO_ROOT = TEST_DIR.parent
LOG_DIR = SCRIPT_DIR / "logs"
LOG_DIR.mkdir(exist_ok=True)
# run_tests.sh sets this so the unit and e2e phases of one run share a single log file.
LOG_FILE_ENV_VAR = "PRIVMX_TEST_LOG_FILE"

MAX_WORKERS = 4
TIMEOUT_PER_TEST = 300
RETRY_COUNT = 1
RETRY_DELAY = 5
DEFAULT_BRIDGE_DOCKER_IMAGE = "privmx-bridge:latest"
# The bridge container is disposable, so it does not need docker's default 10s grace period.
STOP_GRACE_SECONDS = 1

timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")


def resolve_log_file() -> Path:
    configured = os.environ.get(LOG_FILE_ENV_VAR)
    if not configured:
        return LOG_DIR / f"{timestamp}.log"
    log_file = Path(configured).expanduser().resolve()
    log_file.parent.mkdir(parents=True, exist_ok=True)
    return log_file


LOG_FILE = resolve_log_file()

_log_lock = threading.Lock()


def log(msg: str) -> None:
    with _log_lock:
        with open(LOG_FILE, "a", encoding="utf-8") as file_handle:
            file_handle.write(msg + "\n")


def clock_now() -> str:
    return datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]


def format_elapsed(seconds: float) -> str:
    total_seconds = int(seconds)
    return f"{total_seconds // 3600:02d}:{total_seconds % 3600 // 60:02d}:{total_seconds % 60:02d}"


def decode_output(data: bytes | str) -> str:
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")
    return data


def format_command(cmd: Sequence[str]) -> str:
    return shlex.join(str(part) for part in cmd)


def run_command(cmd: Sequence[str], timeout: int | None = None) -> tuple[int, bytes, bytes]:
    command = [str(part) for part in cmd]
    log(f"$ {format_command(command)}")
    try:
        proc = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as exc:
        return 127, b"", str(exc).encode("utf-8", errors="replace")

    try:
        stdout, stderr = proc.communicate(timeout=timeout)
        return proc.returncode, stdout, stderr
    except subprocess.TimeoutExpired:
        proc.kill()
        return -1, b"", b"TIMEOUT"


def require_command_success(
    cmd: Sequence[str],
    timeout: int | None = None,
    action: str | None = None,
) -> tuple[bytes, bytes]:
    rc, out, err = run_command(cmd, timeout=timeout)
    if rc != 0:
        message = decode_output(err).strip() or decode_output(out).strip() or "unknown error"
        action_name = action or format_command(cmd)
        raise RuntimeError(f"{action_name} failed with exit {rc}: {message}")
    return out, err
