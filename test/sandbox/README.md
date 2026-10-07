# group_sandbox

Performance and usage scenarios for tree-backed (Trellis) groups, run against a live Bridge. Not part of the
e2e suite: it is a gtest binary only so it can reuse the e2e fixtures; the filter picks the scenario.

## 1. Bridge

Needs MongoDB on `localhost:27017` and the `endpoint_e2e_testing_network` docker network (see `test/env/compose.yaml`).

```bash
test/runner/.venv/bin/python test/sandbox/start_bridge.py --start-bridge --index 900 \
    --docker-image privmx-bridge:c1-tree-v2 --dataset-dir test/env/datasets/Dataset
```

Same as `e2e_runner.py --start-bridge`, plus `-e PMX_MAX_GROUP_ROTATIONS_PER_HOUR=100000`: removals and key
rotations share a per-group budget (default 10/h, `GROUP_ROTATION_RATE_LIMIT`), and P4/P5 do dozens per group.
Override with `SANDBOX_BRIDGE_ENV="PMX_MAX_GROUP_ROTATIONS_PER_HOUR=... OTHER=..."`. Use the venv python, otherwise
the runner re-execs itself into it and the env injection is lost.

A concurrent `e2e_runner.py` run regenerates `test/env/datasets/Dataset` (new solution id: "Solution does not exist"),
so for long runs point `--dataset-dir` and `-i` at a private copy (`cp -R test/env/datasets/Dataset /tmp/sbx-dataset`).

Index 900 (port 3901, container `privmx_e2e_worker_900`, db `privmx_e2e_db_900`) keeps clear of a concurrent e2e
run, whose worker index is the test's ordinal and walks through low numbers.

## 2. Build and run

```bash
G=<conan generators dir>; source $G/conanbuild.sh
cmake --build build --target group_sandbox            # needs PRIVMX_ENABLE_TESTS_E2E=ON
source $G/conanrun.sh
build/test/group_sandbox -b localhost:3901 -i test/env/datasets/Dataset/ServerData.ini \
    --gtest_filter='GroupSandbox.P*' --out results.jsonl
```

| flag | default | used by |
|---|---|---|
| `--sizes` / `--reps` | `16,64,256,1024,4096` / `1` | P1, P2, P3 (reps: rows per size, take medians) |
| `--ks` / `--ladder-n` | `1,8,32` / `64` | P4 |
| `--blank-n` / `--heal-clients` | `256` / `16` | P5 |
| `--concurrent-n` | `64` | U3 |
| `--out` | `group_sandbox.jsonl` (appended) | all |
| `--mongo-container` / `--mongo-db` | `privmx_test_mongo_c1` / `privmx_e2e_db_900` | server-side sizes (`docker exec ... mongosh`) |

Scenarios: `P1_create`, `P2_add_remove`, `P3_cold_join`, `P4_ladder`, `P5_blanks_self_update`, `U1_thread_removal`,
`U2_store_late_joiner`, `U3_concurrent_managers`, `U4_inbox_anonymous`. Each prints one row per case and appends
the same row as JSON to `--out`. Boolean fields are assertions (the test fails when one is false), except
`removed_reads_old`, which is only observed. Exceptions become an `error` field on the row.

Members beyond the dataset's user_1..3 are registered with `context/addUserToContext` using `[Api]` from the ini;
they stay offline unless a scenario connects them. Groups are not deleted; dropping the Bridge drops its db.
