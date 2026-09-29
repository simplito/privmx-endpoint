# Scripts

Building, testing and tooling scripts. They all operate on the repository root, whichever directory they are called from.

| Script | Purpose |
|--------|---------|
| `./scripts/build.sh` | Debug build via Conan, with unit and e2e tests enabled |
| `./scripts/build-clang.sh` | Same as `build.sh`, but with the Clang toolchain |
| `./scripts/build-with-streams.sh` | Same as `build.sh`, plus `PRIVMX_BUILD_WITH_WEBRTC=ON` (needs `libwebrtc`) |
| `./scripts/doc-gen.sh` | Generate Doxygen documentation into `doc/` |
| `./scripts/run_tests.sh` | Run the unit and e2e test suites |
| `./scripts/bridge.sh` | Start one Bridge seeded with a dataset, for manual testing |
| `./scripts/dataset.sh` | Create or refresh a Bridge test dataset |
| `./scripts/clang-format.sh` | Format the `endpoint/` sources |
| `scripts/completion.bash` | Bash completion for `run_tests.sh` and `bridge.sh` |

The build scripts are unattended Conan + CMake builds into `build/`; see the [build instructions](../README.md#building) for the manual steps and the available CMake options.

## Running tests

Unit tests need only a build; e2e tests additionally need Docker, and start a Bridge per test worker.

```bash
./scripts/run_tests.sh                                  # unit + e2e
./scripts/run_tests.sh --unit-only
./scripts/run_tests.sh --e2e-only --filter 'ThreadTest.*'
```

| Option | Description |
|--------|-------------|
| `--unit-only` / `--e2e-only` | Run just one of the suites |
| `--filter PATTERN` | GTest filter, e.g. `ThreadTest.*` (alias: `--test`) |
| `--build-dir DIR` | Where to look for test binaries (default: `build`) |
| `--e2e-workers N` | e2e tests to run in parallel (default: 4) |
| `--dataset-dir DIR` | Dataset used to seed the Bridge |
| `--bridge-image IMAGE` | Bridge docker image for e2e tests |
| `--keep-bridge` | Leave the Bridge containers up after the run |

## Running a Bridge manually

Starts a single Bridge loaded with a dataset and leaves it running until `Ctrl+C`, which tears it down again. The compose backend from [`test/env/compose.yaml`](../test/env/compose.yaml) is started first if it is not already up.

```bash
./scripts/bridge.sh                                     # Dataset, on http://localhost:3001
./scripts/bridge.sh --dataset Dataset_group --index 1   # another Bridge, on port 3002
```

| Option | Description |
|--------|-------------|
| `--dataset NAME\|DIR` | Dataset name under `test/env/datasets/`, or a path (default: `Dataset`) |
| `--index N` | Worker index: container `privmx_e2e_worker_N` on port `3001 + N` (default: 0) |
| `--bridge-image IMAGE` | Bridge docker image |
| `--keep-backend` | Leave the compose backend (mongo, janus, coturn) running on exit |

## Datasets

Datasets live in `test/env/datasets/`; each holds a `ServerData.ini` with the solution, context and user keys to connect with.

```bash
./scripts/dataset.sh <name>     # create a new dataset, or refresh <name> in place
```

## Shell completion

```bash
source scripts/completion.bash
```

Completes the options of `run_tests.sh` and `bridge.sh`, plus GTest names for `--filter` (scraped from the test sources) and dataset names for `--dataset`.
