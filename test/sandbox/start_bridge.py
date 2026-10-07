"""Starts a sandbox Bridge exactly like `e2e_runner.py --start-bridge`, plus extra `docker run -e` vars.

The runner has no env pass-through, so this wraps it and splices SANDBOX_BRIDGE_ENV into its `docker run`.
Run it with the runner's venv python so the runner does not re-exec itself (and drop the patch):
    test/runner/.venv/bin/python test/sandbox/start_bridge.py --start-bridge --index 900 \
        --docker-image privmx-bridge:c1-tree-v2 --dataset-dir test/env/datasets/Dataset
"""
import os
import runpy
import sys
from pathlib import Path

RUNNER = Path(__file__).resolve().parent.parent / "runner"
sys.path.insert(0, str(RUNNER))
import e2e_common  # noqa: E402

# Removals and rotations share a per-group budget (default 10/h); the perf scenarios do dozens per group.
EXTRA_ENV = os.environ.get("SANDBOX_BRIDGE_ENV", "PMX_MAX_GROUP_ROTATIONS_PER_HOUR=100000").split()

_run = e2e_common.require_command_success


def _with_env(cmd, *args, **kwargs):
    cmd = list(cmd)
    if cmd[:3] == ["docker", "run", "-d"]:
        cmd[3:3] = [part for var in EXTRA_ENV for part in ("-e", var)]
    return _run(cmd, *args, **kwargs)


e2e_common.require_command_success = _with_env
sys.argv = [str(RUNNER / "e2e_runner.py"), *sys.argv[1:]]
runpy.run_path(sys.argv[0], run_name="__main__")
