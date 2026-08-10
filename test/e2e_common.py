from __future__ import annotations

import datetime
import shlex
import subprocess
import threading
from pathlib import Path
from typing import Sequence

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
LOG_DIR = SCRIPT_DIR / "logs"
LOG_DIR.mkdir(exist_ok=True)

MAX_WORKERS = 4
TIMEOUT_PER_TEST = 300
RETRY_COUNT = 1
RETRY_DELAY = 5

timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE = LOG_DIR / f"{timestamp}.log"

_log_lock = threading.Lock()


def log(msg: str) -> None:
    with _log_lock:
        with open(LOG_FILE, "a", encoding="utf-8") as file_handle:
            file_handle.write(msg + "\n")


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
