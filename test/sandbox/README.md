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
rotations share a per-group budget (default 60/h, `GROUP_ROTATION_RATE_LIMIT`), and P4/P5 do dozens per group.
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
| `--blank-n` / `--heal-clients` / `--heal-wait` | `256` / `16` / `35` (s) | P5 (`--heal-clients`, `--heal-wait` also P6) |
| `--creator-n` | `1024` | P6 |
| `--late-k` | `4` | U5 |
| `--concurrent-n` | `64` | U3 |
| `--out` | `group_sandbox.jsonl` (appended) | all |
| `--mongo-container` / `--mongo-db` | `privmx_test_mongo_c1` / `privmx_e2e_db_900` | server-side sizes (`docker exec ... mongosh`) |

Perf scenarios `S1_create` … `S9_concurrent_managers` (perf-16k run; flags `--s4-sizes`, `--s5-n`, `--s6-n`,
`--s6-ks`, `--storm-idle`, `--s7-n`, `--s7-k`, `--s8-n`, `--s8-calls`, `--s9-n`) bracket every measured phase with a
marker request (`context/getContext`, logged by the Bridge's RequestLogger) and append the phase name to `--markers`.
`perf_parse.py <bridge log> <markers> [cpu log]` then sums the Bridge calls, server ms and bytes per phase. Keep one
markers file per Bridge lifetime, since the k-th marker in the log is the k-th line of the file. `--pool-file` keeps
registered users across processes (same Bridge db), and `--reg-threads` (default 16) registers them in parallel.

Scenarios: `P1_create`, `P2_add_remove`, `P3_cold_join`, `P4_ladder`, `P5_blanks_self_update`, `P6_creator_removal`,
`U1_thread_removal`, `U2_store_late_joiner`, `U3_concurrent_managers`, `U4_inbox_anonymous`, `U5_late_joiner_ladder`.
Review scenarios: `R1_epoch_isolation` (`--r1-n`, `--r1-k`: epoch growth on a tree kept dense by removing a
bucket-0 member and re-adding; then pinned catch-up, cold `getGroup`, warm encrypt/decrypt loops, 32 MiB file in
4 MiB vs 1 MiB chunks) and `R2_thread_hot_path_single_group` (`--r2-n`: thread calls by a member of exactly one group
vs a plain thread user). Each prints one row per case and appends
the same row as JSON to `--out`. Boolean fields are assertions (the test fails when one is false), except
`removed_reads_old`, which is only observed. Exceptions become an `error` field on the row.

Members beyond the dataset's user_1..3 are registered with `context/addUserToContext` using `[Api]` from the ini;
they stay offline unless a scenario connects them. Groups are not deleted; dropping the Bridge drops its db.
