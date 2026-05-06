from __future__ import annotations

import argparse
import datetime
import fnmatch
import importlib.util
import json
import os
import re
import shlex
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

REQUIRED_MODULES = ("requests", "pymongo")
SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
MANAGED_VENV_DIR = SCRIPT_DIR / ".venv"
REQUIREMENTS_FILE = SCRIPT_DIR / "requirements.txt"
LOG_DIR = SCRIPT_DIR / "logs"
LOG_DIR.mkdir(exist_ok=True)
TEST_CMAKE_FILE = SCRIPT_DIR / "CMakeLists.txt"

MAX_WORKERS = 4
TIMEOUT_PER_TEST = 300
RETRY_COUNT = 0
RETRY_DELAY = 5

timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE = LOG_DIR / f"{timestamp}.log"

requests = None
MongoClient = None

_log_lock = threading.Lock()


@dataclass
class BridgeInfo:
    host_port: int
    container_name: str
    mongo_url: str
    db: Any
    mongo_client: Any


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


def managed_python_path() -> Path:
    if os.name == "nt":
        return MANAGED_VENV_DIR / "Scripts" / "python.exe"
    return MANAGED_VENV_DIR / "bin" / "python"


def is_running_in_managed_venv() -> bool:
    try:
        return Path(sys.prefix).resolve() == MANAGED_VENV_DIR.resolve()
    except OSError:
        return False


def find_missing_modules() -> list[str]:
    return [module_name for module_name in REQUIRED_MODULES if importlib.util.find_spec(module_name) is None]


def bootstrap_python_environment() -> Path:
    if not REQUIREMENTS_FILE.exists():
        raise SystemExit(f"Missing Python requirements file: {REQUIREMENTS_FILE}")

    if not MANAGED_VENV_DIR.exists():
        print(f"Creating Python virtual environment in {MANAGED_VENV_DIR}")
        subprocess.check_call([sys.executable, "-m", "venv", str(MANAGED_VENV_DIR)])

    managed_python = managed_python_path()
    print(f"Installing Python dependencies from {REQUIREMENTS_FILE}")
    subprocess.check_call([str(managed_python), "-m", "pip", "install", "-r", str(REQUIREMENTS_FILE)])
    return managed_python


def reexec_with_managed_python(argv: Sequence[str], managed_python: Path) -> None:
    env = os.environ.copy()
    env["PRIVMX_E2E_SETUP_DONE"] = "1"
    os.execve(
        str(managed_python),
        [str(managed_python), str(SCRIPT_DIR / "e2e_runner.py"), *argv],
        env,
    )


def ensure_python_environment(argv: Sequence[str], force_setup: bool, has_test_targets: bool) -> None:
    setup_done = os.environ.get("PRIVMX_E2E_SETUP_DONE") == "1"
    missing_modules = find_missing_modules()

    if (force_setup and not setup_done) or missing_modules:
        managed_python = bootstrap_python_environment()
        if not is_running_in_managed_venv():
            print(f"Re-running e2e runner with {managed_python}")
            reexec_with_managed_python(argv, managed_python)

        missing_after_setup = find_missing_modules()
        if missing_after_setup:
            missing_list = ", ".join(missing_after_setup)
            raise SystemExit(f"Python environment is still missing required modules: {missing_list}")

    if force_setup and not has_test_targets:
        print(f"Python environment is ready: {managed_python_path()}")
        raise SystemExit(0)


def load_runtime_dependencies() -> None:
    global requests, MongoClient

    import requests as requests_module
    from pymongo import MongoClient as mongo_client_class

    requests = requests_module
    MongoClient = mongo_client_class


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


def print_container_logs(container_name: str) -> None:
    try:
        print(f"\n--- LOGS FOR {container_name} ---")
        rc, stdout, stderr = run_command(["docker", "logs", "--tail", "50", container_name])
        if rc == 0:
            print(decode_output(stdout))
        else:
            print(f"Could not retrieve container logs (exit {rc}): {decode_output(stderr)}")
        print("--- END LOGS ---\n")
    except Exception:
        print("Could not retrieve container logs.")


def load_mongo_dataset(db: Any, dataset_path: str) -> None:
    full_path = Path(dataset_path) / "mongo_collections"
    if not full_path.exists():
        return

    for file_path in sorted(full_path.iterdir()):
        if file_path.suffix != ".json":
            continue

        collection_name = file_path.stem
        try:
            with open(file_path, "r", encoding="utf-8") as file_handle:
                docs = json.load(file_handle)

            if isinstance(docs, list) and docs:
                db[collection_name].insert_many(docs)
        except Exception as exc:
            print(f"Failed to load {file_path.name}: {exc}")


def load_bridge_dataset(dataset_path: str, bridge_container_name: str) -> None:
    full_path = Path(dataset_path) / "storage"
    if not full_path.exists():
        return

    require_command_success(
        ["docker", "cp", str(full_path), f"{bridge_container_name}:/work/privmx-bridge"],
        action="Loading bridge dataset",
    )


def wait_for_server_ready(port: int, container_name: str, timeout_seconds: int = 10) -> None:
    url = f"http://localhost:{port}/privmx-configuration.json"
    deadline = time.time() + timeout_seconds

    while time.time() < deadline:
        try:
            stdout, _ = require_command_success(
                ["docker", "inspect", "-f", "{{.State.Running}}", container_name],
                action=f"Checking container state for {container_name}",
            )
            is_running = decode_output(stdout).strip()
            if is_running != "true":
                print_container_logs(container_name)
                raise RuntimeError(f"Container {container_name} stopped unexpectedly.")
        except Exception as exc:
            raise RuntimeError(f"Container check failed: {exc}") from exc

        try:
            response = requests.get(url, timeout=2)
            if response.ok:
                return
        except Exception:
            pass

        time.sleep(0.2)

    print_container_logs(container_name)
    raise RuntimeError(f"Server failed to start on port {port} within {timeout_seconds}s")


def create_bridge_docker(index: int, docker_image: str) -> BridgeInfo:
    host_port = 3001 + index
    container_name = f"privmx_e2e_worker_{index}"
    db_name = f"privmx_e2e_db_{index}"
    internal_mongo_url = f"mongodb://test_mongodb:27017/{db_name}"
    local_mongo_url = f"mongodb://localhost:27017/{db_name}?directConnection=true"

    env_list = [
        "PRIVMX_PORT=3000",
        f"PRIVMX_MONGO_URL={internal_mongo_url}",
        "PRIVMX_WORKERS=1",
        "PMX_MIGRATION=Migration_069_Indexes_for_session",
        "PMX_MEDIA_SERVER_ALLOW_SELF_SIGNED_CERTS=true",
        "PMX_STREAM_ENABLED=true",
        "PRIVMX_HOSTNAME=0.0.0.0",
        "PMX_STREAMS_MEDIA_SERVER=janus",
        "PMX_STREAMS_TURN_SERVER=turn:127.0.0.1:3478",
        "PMX_STREAMS_TURN_SERVER_SECRET=my-secret-key",
    ]

    mongo_client = MongoClient(local_mongo_url)
    run_command(["docker", "rm", "-f", container_name])
    mongo_client.drop_database(db_name)

    cmd = [
        "docker",
        "run",
        "-d",
        "--name",
        container_name,
        "-p",
        f"{host_port}:3000",
        "--network",
        "endpoint_e2e_testing_network",
        "--label",
        "com.docker.compose.project=endpoint_e2e_testing",
        "--label",
        "com.docker.compose.service=e2e_worker",
        "--label",
        "com.docker.compose.oneoff=False",
    ]
    for env_var in env_list:
        cmd.extend(["-e", env_var])
    cmd.extend(
        [
            "--add-host",
            "host.docker.internal:host-gateway",
            docker_image,
        ]
    )

    require_command_success(cmd, action=f"Starting bridge container {container_name}")
    wait_for_server_ready(host_port, container_name)

    return BridgeInfo(
        host_port=host_port,
        container_name=container_name,
        mongo_url=internal_mongo_url,
        db=mongo_client[db_name],
        mongo_client=mongo_client,
    )


def destroy_bridge_docker(bridge_info: BridgeInfo) -> None:
    try:
        bridge_info.mongo_client.drop_database(bridge_info.db.name)
        bridge_info.mongo_client.close()
    except Exception:
        pass
    run_command(["docker", "rm", "-f", bridge_info.container_name])


def prepare_bridge_context(bridge_info: BridgeInfo, dataset_dir_path: str) -> None:
    container_name = bridge_info.container_name
    host_port = bridge_info.host_port

    try:
        run_command(["docker", "stop", container_name])
        require_command_success(["docker", "start", container_name], action=f"Starting {container_name}")
        wait_for_server_ready(host_port, container_name)

        run_command(["docker", "stop", container_name])

        load_mongo_dataset(bridge_info.db, dataset_dir_path)
        load_bridge_dataset(dataset_dir_path, container_name)

        require_command_success(["docker", "start", container_name], action=f"Restarting {container_name}")
        wait_for_server_ready(host_port, container_name)
    except Exception:
        run_command(["docker", "stop", container_name])
        raise


def normalize_gtest_entry(entry: str) -> str:
    return entry.split(" #", 1)[0].strip()


def list_tests(test_file_path: str, passthrough_args: Sequence[str]) -> list[str]:
    return_code, out, err = run_command([test_file_path, "--gtest_list_tests", *passthrough_args])
    if return_code != 0:
        print(f"Failed to load tests list for {test_file_path}")
        print("Received error:")
        print(decode_output(err))
        raise SystemExit(1)

    tests: list[str] = []
    suite = ""
    for raw_line in decode_output(out).splitlines():
        if not raw_line.strip():
            continue
        if not raw_line.startswith("  "):
            suite = normalize_gtest_entry(raw_line)
        else:
            tests.append(f"{suite}{normalize_gtest_entry(raw_line)}")
    return tests


def pre_test(index: int, dataset_dir_path: str, test_name: str) -> BridgeInfo:
    log(f"[PRE-TEST] {test_name}")
    bridge_info = create_bridge_docker(index, "simplito/privmx-bridge:latest")
    try:
        prepare_bridge_context(bridge_info, dataset_dir_path)
        return bridge_info
    except Exception:
        destroy_bridge_docker(bridge_info)
        raise


def post_test(test_name: str, bridge_info: BridgeInfo) -> None:
    log(f"[POST-TEST] {test_name}")
    destroy_bridge_docker(bridge_info)


def execute_test(
    test_file_path: str,
    test_name: str,
    init_file_path: str,
    bridge_info: BridgeInfo,
    passthrough_args: Sequence[str],
) -> tuple[bool, int, bytes, bytes]:
    command = [
        test_file_path,
        "-i",
        init_file_path,
        "-b",
        f"localhost:{bridge_info.host_port}",
        *passthrough_args,
        f"--gtest_filter={test_name}",
    ]
    rc, out, err = run_command(command, timeout=TIMEOUT_PER_TEST)
    log("=" * 80)
    log(decode_output(out))
    log(decode_output(err))
    return rc == 0, rc, out, err


def run_single_test(
    index: int,
    test_file_path: str,
    test_name: str,
    init_file_path: str,
    dataset_dir_path: str,
    passthrough_args: Sequence[str],
) -> tuple[str, bool, int, bytes | str, bytes | str]:
    last_result: tuple[str, bool, int, bytes | str, bytes | str] = (test_name, False, -1, b"", b"")

    for attempt in range(1, RETRY_COUNT + 2):
        bridge_info: BridgeInfo | None = None
        try:
            bridge_info = pre_test(index, dataset_dir_path, test_name)
            print(f"Running: {test_name}")
            success, rc, out, err = execute_test(
                test_file_path,
                test_name,
                init_file_path,
                bridge_info,
                passthrough_args,
            )
            log(f"[TEST] {test_name} (attempt {attempt})")
            last_result = (test_name, success, rc, out, err)
            if success:
                return last_result
        except Exception as exc:
            log(f"[ERROR] {test_name}: {exc}")
            last_result = (test_name, False, -1, b"", str(exc))
        finally:
            if bridge_info is not None:
                post_test(test_name, bridge_info)

        if attempt <= RETRY_COUNT:
            time.sleep(RETRY_DELAY)

    return last_result


def print_result(test_name: str, success: bool, rc: int, out: bytes | str, err: bytes | str) -> None:
    if success:
        print(f"Success - {test_name}")
        return

    print(f"Failed  - {test_name} (exit={rc})")
    print("----- STDOUT -----")
    print(decode_output(out))
    print("----- STDERR -----")
    print(decode_output(err))
    print("------------------")


def candidate_input_paths(path_arg: str) -> list[Path]:
    path = Path(path_arg).expanduser()
    if path.is_absolute():
        return [path.resolve()]

    candidates: list[Path] = []
    seen: set[Path] = set()
    for base_dir in (Path.cwd(), SCRIPT_DIR, REPO_ROOT):
        candidate = (base_dir / path).resolve()
        if candidate not in seen:
            seen.add(candidate)
            candidates.append(candidate)
    return candidates


def resolve_input_path(path_arg: str) -> str:
    candidates = candidate_input_paths(path_arg)
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    return str(candidates[0])


def contains_e2e_binaries(path: Path) -> bool:
    if not path.is_dir():
        return False
    return any(child.is_file() and child.name.startswith("test_e2e_") for child in path.iterdir())


def resolve_tests_dir_path(path_arg: str) -> str:
    resolved_path = Path(resolve_input_path(path_arg))
    if contains_e2e_binaries(resolved_path):
        return str(resolved_path)

    nested_test_dir = resolved_path / "test"
    if contains_e2e_binaries(nested_test_dir):
        return str(nested_test_dir.resolve())

    return str(resolved_path)


def configured_test_binary_names() -> set[str]:
    if not TEST_CMAKE_FILE.exists():
        return set()

    cmake_contents = TEST_CMAKE_FILE.read_text(encoding="utf-8")
    return set(re.findall(r"add_executable\((test_e2e_[^\s\)]+)", cmake_contents))


def extract_positive_gtest_patterns(selected_filter: str | None) -> list[str]:
    if not selected_filter:
        return []

    positive_part, _, _ = selected_filter.partition("-")
    patterns = [pattern for pattern in positive_part.split(":") if pattern]
    return patterns or ["*"]


def suite_pattern_from_gtest_pattern(pattern: str) -> str | None:
    suite_pattern = pattern.split(".", 1)[0]
    if not suite_pattern or suite_pattern == "*":
        return None
    return suite_pattern


def select_test_files_for_filter(test_files: list[Path], selected_filter: str | None) -> list[Path]:
    positive_patterns = extract_positive_gtest_patterns(selected_filter)
    if not positive_patterns:
        return test_files

    suite_patterns: list[str] = []
    for pattern in positive_patterns:
        suite_pattern = suite_pattern_from_gtest_pattern(pattern)
        if suite_pattern is None:
            return test_files
        suite_patterns.append(suite_pattern)

    filtered_files = [
        path
        for path in test_files
        if any(fnmatch.fnmatch(path.name, f"test_e2e_{suite_pattern}") for suite_pattern in suite_patterns)
    ]
    return filtered_files or test_files


def discover_test_files(test_dir: Path, selected_filter: str | None) -> list[Path]:
    test_files = sorted(
        path for path in test_dir.iterdir() if path.is_file() and path.name.startswith("test_e2e_")
    )

    configured_names = configured_test_binary_names()
    if configured_names:
        stale_files = [path.name for path in test_files if path.name not in configured_names]
        if stale_files:
            log(f"Skipping stale e2e binaries not defined in CMake: {', '.join(stale_files)}")

        configured_files = [path for path in test_files if path.name in configured_names]
        if configured_files:
            test_files = configured_files

    return select_test_files_for_filter(test_files, selected_filter)


def validate_passthrough_args(parser: argparse.ArgumentParser, passthrough_args: Sequence[str]) -> None:
    forbidden_prefixes = (
        "--ini_file_path=",
        "--bridge_url=",
    )
    forbidden_args = {
        "-i",
        "--ini_file_path",
        "-b",
        "--bridge_url",
        "--gtest_list_tests",
    }
    for arg in passthrough_args:
        if arg in forbidden_args or any(arg.startswith(prefix) for prefix in forbidden_prefixes):
            parser.error(
                f"argument '{arg}' is managed by e2e_runner and cannot be forwarded to the test executables"
            )


def extract_gtest_filter(passthrough_args: Sequence[str]) -> tuple[str | None, list[str]]:
    filter_value: str | None = None
    forwarded_args: list[str] = []
    waiting_for_filter_value = False

    for arg in passthrough_args:
        if waiting_for_filter_value:
            filter_value = arg
            waiting_for_filter_value = False
            continue
        if arg == "--gtest_filter":
            waiting_for_filter_value = True
            continue
        if arg.startswith("--gtest_filter="):
            filter_value = arg.split("=", 1)[1]
            continue
        forwarded_args.append(arg)

    if waiting_for_filter_value:
        raise ValueError("Missing value for --gtest_filter")

    return filter_value, forwarded_args


def parse_cli_args(argv: Sequence[str]) -> tuple[argparse.Namespace, str | None, list[str]]:
    parser = argparse.ArgumentParser(
        description="Run privmx endpoint e2e GTest binaries with managed Docker fixtures.",
        epilog=(
            "Examples:\n"
            "  python3 e2e_runner.py --setup-python\n"
            "  python3 e2e_runner.py build test_env/create_dataset/ServerData.ini "
            "test_env/create_dataset/Dataset --gtest_filter=CoreTest.*\n"
            "  python3 e2e_runner.py build test_env/create_dataset/ServerData.ini "
            "test_env/create_dataset/Dataset -- --gtest_repeat=2"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--setup-python",
        action="store_true",
        help="Create/update test/.venv and install Python dependencies before running tests.",
    )
    parser.add_argument("tests_dir", nargs="?")
    parser.add_argument("init_file_path", nargs="?")
    parser.add_argument("dataset_dir", nargs="?")

    args, passthrough_args = parser.parse_known_args(argv)
    passthrough_args = [arg for arg in passthrough_args if arg != "--"]

    has_any_target = any(
        value is not None for value in (args.tests_dir, args.init_file_path, args.dataset_dir)
    )
    has_all_targets = all(
        value is not None for value in (args.tests_dir, args.init_file_path, args.dataset_dir)
    )

    if has_any_target and not has_all_targets:
        parser.error("tests_dir, init_file_path and dataset_dir must be provided together")
    if not args.setup_python and not has_all_targets:
        parser.error("tests_dir, init_file_path and dataset_dir are required")

    validate_passthrough_args(parser, passthrough_args)
    try:
        gtest_filter, forwarded_args = extract_gtest_filter(passthrough_args)
    except ValueError as exc:
        parser.error(str(exc))

    return args, gtest_filter, forwarded_args


def build_list_passthrough_args(selected_filter: str | None) -> list[str]:
    if selected_filter is None:
        return []
    return [f"--gtest_filter={selected_filter}"]


def validate_input_paths(test_dir_path: str, init_file_path: str, dataset_dir_path: str) -> None:
    missing_paths = [
        path
        for path in (test_dir_path, init_file_path, dataset_dir_path)
        if not Path(path).exists()
    ]
    if missing_paths:
        formatted = "\n".join(missing_paths)
        raise SystemExit(f"Required path does not exist:\n{formatted}")


def main(
    test_dir_path: str,
    init_file_path: str,
    dataset_dir_path: str,
    run_passthrough_args: Sequence[str],
    selected_filter: str | None,
) -> int:
    validate_input_paths(test_dir_path, init_file_path, dataset_dir_path)

    test_dir = Path(test_dir_path)
    test_files = discover_test_files(test_dir, selected_filter)
    if not test_files:
        print(f"No e2e test executables found in {test_dir_path}")
        return 1

    failed: list[str] = []
    scheduled_tests = 0
    list_passthrough_args = build_list_passthrough_args(selected_filter)

    for test_file in test_files:
        tests = list_tests(str(test_file), list_passthrough_args)
        if not tests:
            continue

        scheduled_tests += len(tests)
        print(f"Found {len(tests)} tests in {test_file}")
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = [
                executor.submit(
                    run_single_test,
                    idx,
                    str(test_file),
                    test_name,
                    init_file_path,
                    dataset_dir_path,
                    run_passthrough_args,
                )
                for idx, test_name in enumerate(tests)
            ]

            for future in as_completed(futures):
                test_name, success, rc, out, err = future.result()
                print_result(test_name, success, rc, out, err)
                if not success:
                    failed.append(test_name)

    if scheduled_tests == 0:
        filter_suffix = f" for filter '{selected_filter}'" if selected_filter else ""
        print(f"No tests matched{filter_suffix}.")
        return 1

    print("\n=========================")
    print(f"log file    : {LOG_FILE}")
    print(f"failed tests: {failed}")
    print("=========================")
    return len(failed)


if __name__ == "__main__":
    args, selected_filter, run_passthrough_args = parse_cli_args(sys.argv[1:])
    has_test_targets = all(
        value is not None for value in (args.tests_dir, args.init_file_path, args.dataset_dir)
    )

    ensure_python_environment(sys.argv[1:], args.setup_python, has_test_targets)
    load_runtime_dependencies()

    if not has_test_targets:
        raise SystemExit(0)

    test_dir_path = resolve_tests_dir_path(args.tests_dir)
    init_file_path = resolve_input_path(args.init_file_path)
    dataset_dir_path = resolve_input_path(args.dataset_dir)

    result = main(
        test_dir_path,
        init_file_path,
        dataset_dir_path,
        run_passthrough_args,
        selected_filter,
    )
    raise SystemExit(0 if result == 0 else 1)
