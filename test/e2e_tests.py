from __future__ import annotations

import fnmatch
import re
import time
from pathlib import Path
from typing import Sequence

import e2e_common
from e2e_bridge import BridgeInfo, create_bridge_docker, destroy_bridge_docker, prepare_bridge_context

TEST_CMAKE_FILE = e2e_common.SCRIPT_DIR / "CMakeLists.txt"


def normalize_gtest_entry(entry: str) -> str:
    return entry.split(" #", 1)[0].strip()


def list_tests(test_file_path: str, passthrough_args: Sequence[str]) -> list[str]:
    return_code, out, err = e2e_common.run_command([test_file_path, "--gtest_list_tests", *passthrough_args])
    if return_code != 0:
        print(f"Failed to load tests list for {test_file_path}")
        print("Received error:")
        print(e2e_common.decode_output(err))
        raise SystemExit(1)

    tests: list[str] = []
    suite = ""
    for raw_line in e2e_common.decode_output(out).splitlines():
        if not raw_line.strip():
            continue
        if not raw_line.startswith("  "):
            suite = normalize_gtest_entry(raw_line)
        else:
            tests.append(f"{suite}{normalize_gtest_entry(raw_line)}")
    return tests


def pre_test(index: int, dataset_dir_path: str, test_name: str) -> BridgeInfo:
    e2e_common.log(f"[PRE-TEST] {test_name}")
    bridge_info = create_bridge_docker(index, e2e_common.DEFAULT_BRIDGE_DOCKER_IMAGE, dataset_dir_path)
    try:
        prepare_bridge_context(bridge_info, dataset_dir_path)
        return bridge_info
    except Exception:
        destroy_bridge_docker(bridge_info)
        raise


def post_test(test_name: str, bridge_info: BridgeInfo) -> None:
    e2e_common.log(f"[POST-TEST] {test_name}")
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
    rc, out, err = e2e_common.run_command(command, timeout=e2e_common.TIMEOUT_PER_TEST)
    e2e_common.log("=" * 80)
    e2e_common.log(e2e_common.decode_output(out))
    e2e_common.log(e2e_common.decode_output(err))
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

    for attempt in range(1, e2e_common.RETRY_COUNT + 2):
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
            e2e_common.log(f"[TEST] {test_name} (attempt {attempt})")
            last_result = (test_name, success, rc, out, err)
            if success:
                return last_result
        except Exception as exc:
            e2e_common.log(f"[ERROR] {test_name}: {exc}")
            last_result = (test_name, False, -1, b"", str(exc))
        finally:
            if bridge_info is not None:
                post_test(test_name, bridge_info)

        if attempt <= e2e_common.RETRY_COUNT:
            time.sleep(e2e_common.RETRY_DELAY)

    return last_result


def print_result(test_name: str, success: bool, rc: int, out: bytes | str, err: bytes | str) -> None:
    if success:
        print(f"Success - {test_name}")
        return

    print(f"Failed  - {test_name} (exit={rc})")
    print("----- STDOUT -----")
    print(e2e_common.decode_output(out))
    print("----- STDERR -----")
    print(e2e_common.decode_output(err))
    print("------------------")


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
            e2e_common.log(f"Skipping stale e2e binaries not defined in CMake: {', '.join(stale_files)}")

        configured_files = [path for path in test_files if path.name in configured_names]
        if configured_files:
            test_files = configured_files

    return select_test_files_for_filter(test_files, selected_filter)


def build_list_passthrough_args(selected_filter: str | None) -> list[str]:
    if selected_filter is None:
        return []
    return [f"--gtest_filter={selected_filter}"]
