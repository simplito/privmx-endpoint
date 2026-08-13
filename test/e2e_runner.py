from __future__ import annotations

import argparse
import importlib.util
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Sequence

import e2e_common
from e2e_bridge import check_backend_ready, load_runtime_dependencies
from e2e_tests import (
    build_list_passthrough_args,
    discover_test_files,
    list_tests,
    print_result,
    run_single_test,
)

REQUIRED_MODULES = ("requests", "pymongo")
MANAGED_VENV_DIR = e2e_common.SCRIPT_DIR / ".venv"
REQUIREMENTS_FILE = e2e_common.SCRIPT_DIR / "requirements.txt"
DEFAULT_TESTS_DIR = "build"
DEFAULT_DATASET_DIR = "test/test_env/create_dataset/Dataset"


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
        [str(managed_python), str(e2e_common.SCRIPT_DIR / "e2e_runner.py"), *argv],
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


def candidate_input_paths(path_arg: str) -> list[Path]:
    path = Path(path_arg).expanduser()
    if path.is_absolute():
        return [path.resolve()]

    candidates: list[Path] = []
    seen: set[Path] = set()
    for base_dir in (Path.cwd(), e2e_common.SCRIPT_DIR, e2e_common.REPO_ROOT):
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
            "  python3 e2e_runner.py\n"
            "  python3 e2e_runner.py --tests-dir build --dataset-dir test_env/create_dataset/Dataset --gtest_filter=CoreTest.*\n"
            "  python3 e2e_runner.py --tests-dir build --dataset-dir test_env/create_dataset/Dataset -- --gtest_repeat=2"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--setup-python",
        action="store_true",
        help="Create/update test/.venv and install Python dependencies before running tests.",
    )
    parser.add_argument(
        "--max-workers",
        type=int,
        default=e2e_common.MAX_WORKERS,
        metavar="N",
        help=f"Maximum number of tests to run in parallel (default: {e2e_common.MAX_WORKERS}).",
    )
    parser.add_argument(
        "--tests-dir",
        help=f"Directory containing the e2e test binaries (default: {DEFAULT_TESTS_DIR}).",
    )
    parser.add_argument(
        "--dataset-dir",
        help=f"Dataset directory used to seed the bridge (default: {DEFAULT_DATASET_DIR}).",
    )

    args, passthrough_args = parser.parse_known_args(argv)
    passthrough_args = [arg for arg in passthrough_args if arg != "--"]

    validate_passthrough_args(parser, passthrough_args)
    try:
        gtest_filter, forwarded_args = extract_gtest_filter(passthrough_args)
    except ValueError as exc:
        parser.error(str(exc))

    return args, gtest_filter, forwarded_args


def validate_input_paths(test_dir_path: str, init_file_path: str, dataset_dir_path: str) -> None:
    missing_paths = [
        path
        for path in (test_dir_path, init_file_path, dataset_dir_path)
        if not Path(path).exists()
    ]
    if missing_paths:
        formatted = "\n".join(missing_paths)
        raise SystemExit(f"Required path does not exist:\n{formatted}")


def resolve_dataset_ini_path(dataset_dir_path: str) -> str:
    ini_path = Path(dataset_dir_path) / "ServerData.ini"
    if not ini_path.exists():
        raise SystemExit(f"ServerData.ini not found in dataset directory: {dataset_dir_path}")
    return str(ini_path)


def main(
    test_dir_path: str,
    init_file_path: str,
    dataset_dir_path: str,
    run_passthrough_args: Sequence[str],
    selected_filter: str | None,
    max_workers: int = e2e_common.MAX_WORKERS,
) -> int:
    validate_input_paths(test_dir_path, init_file_path, dataset_dir_path)

    try:
        check_backend_ready()
    except RuntimeError as exc:
        print(f"Backend not ready: {exc}")
        return 1

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
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
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
    print(f"log file    : {e2e_common.LOG_FILE}")
    print(f"failed tests: {failed}")
    print("=========================")
    return len(failed)


if __name__ == "__main__":
    args, selected_filter, run_passthrough_args = parse_cli_args(sys.argv[1:])
    has_explicit_targets = any(value is not None for value in (args.tests_dir, args.dataset_dir))

    ensure_python_environment(sys.argv[1:], args.setup_python, has_explicit_targets)
    load_runtime_dependencies()

    test_dir_path = resolve_tests_dir_path(args.tests_dir or DEFAULT_TESTS_DIR)
    dataset_dir_path = resolve_input_path(args.dataset_dir or DEFAULT_DATASET_DIR)
    init_file_path = resolve_dataset_ini_path(dataset_dir_path)

    result = main(
        test_dir_path,
        init_file_path,
        dataset_dir_path,
        run_passthrough_args,
        selected_filter,
        args.max_workers,
    )
    raise SystemExit(0 if result == 0 else 1)
