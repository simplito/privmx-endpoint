# Test environment

[`scripts/run_tests.sh`](../scripts/README.md) is the front door for running the suites, and [`scripts/bridge.sh`](../scripts/README.md#running-a-bridge-manually) for a Bridge to poke at by hand. This document describes what sits underneath them — the e2e runner, the backend it needs, and the datasets — for when you want to drive them directly.

## Layout

| Path | Contents |
|------|----------|
| `tests/unit/` | Unit tests: no backend, no Docker |
| `tests/e2e/` | E2E tests: each one runs against its own Bridge |
| `fixtures/` | Shared fixtures and test bases (`BaseTest.hpp`, `BaseGroupTest.hpp`, …), on the include path |
| `runner/e2e_runner.py` | Runner entry point: discovers binaries, schedules tests, manages Bridges |
| `runner/e2e_bridge.py`, `e2e_tests.py`, `e2e_common.py` | Runner internals |
| `runner/logs/` | One log file per runner invocation |
| `env/compose.yaml` | Backend containers: MongoDB (replica set), Janus, Coturn, and the shared docker network |
| `env/datasets/` | The Bridge snapshots tests are seeded from |
| `env/create_dataset/` | The tool that produces those snapshots |
| `tools/` | Key tree dump utilities (see [tools/README.md](tools/README.md)) |

## Prerequisites

Build with `PRIVMX_ENABLE_TESTS` and `PRIVMX_ENABLE_TESTS_E2E` (both are on in the build scripts). When you built with Conan, source the run environment first or every test will fail:

```bash
source build/build/Debug/generators/conanrun.sh
```

### Backend

E2E tests need MongoDB on `localhost:27017` and the `endpoint_e2e_testing_network` docker network — the runner refuses to start without them. Both come from `env/compose.yaml`:

```bash
docker compose up -d      # from test/env/
docker compose down
```

`run_tests.sh` and `bridge.sh` bring this up and tear it down for you; do it by hand only when driving `e2e_runner.py` yourself.

### Python

The runner keeps its own virtual environment in `test/runner/.venv`, built from `runner/requirements.txt` (`requests`, `pymongo`). It bootstraps and re-executes itself on the first run that finds the dependencies missing, so setup is usually automatic. To do it up front:

```bash
python3 test/runner/e2e_runner.py --setup-python
```

### Stream API

Stream tests need at least one video device that is actually streaming. A virtual camera works — for example [akvcam](https://github.com/webcamoid/akvcam):

```bash
git clone https://github.com/webcamoid/akvcam.git
cd akvcam/src/
make
sudo make dkms_install
sudo mkdir -p /etc/akvcam
sudo cat > /etc/akvcam/config.ini << EOF
[Cameras]
cameras/size = 2

cameras/1/type = output
cameras/1/mode = mmap, userptr, rw
cameras/1/description = Virtual Camera (output device)
cameras/1/formats = 1, 2
cameras/1/videonr = 7

cameras/2/type = capture
cameras/2/mode = mmap, rw
cameras/2/description = Virtual Camera
cameras/2/formats = 1, 2
cameras/2/videonr = 9

[Formats]
formats/size = 2

formats/1/format = YUY2
formats/1/width = 640
formats/1/height = 480
formats/1/fps = 30

formats/2/format = RGB24, YUY2
formats/2/width = 640
formats/2/height = 480
formats/2/fps = 20/1, 15/2

[Connections]
connections/size = 1
connections/1/connection = 1:2
EOF
sudo chmod -vf 644 /etc/akvcam/config.ini
```

```bash
sudo modprobe videodev
sudo insmod akvcam.ko
```

## Driving the e2e runner directly

`run_tests.sh` calls this for you; call it yourself when you need flags it does not expose. With no arguments it uses both defaults:

```bash
python3 test/runner/e2e_runner.py
```

| Option | Description |
|--------|-------------|
| `--tests-dir DIR` | Directory with the `test_e2e_*` binaries, or a CMake build root — `build/test` is used automatically when it exists (default: `build`) |
| `--dataset-dir DIR` | Dataset to seed each Bridge with; `ServerData.ini` is read from inside it, so it is never passed separately (default: `test/env/datasets/Dataset`) |
| `--max-workers N` | Tests in parallel (default: 4) |
| `--setup-python` | Create/update `test/runner/.venv` and exit |
| `--start-bridge` | Start one seeded Bridge and block until `Ctrl+C` instead of running tests — this is what `bridge.sh` wraps |
| `--index N` | Worker index for `--start-bridge`: container name and host port `3001 + N` |
| `--docker-image IMAGE` | Bridge image (default: `hub.simplito.com/privmx/privmx-bridge:dev`) |

Each test gets a **freshly created Bridge container and database**, seeded from the dataset and dropped afterwards, and a failing test is retried once. Paths are resolved relative to the current directory, then `test/runner/`, then `test/`, then the repository root, so both of these work:

```bash
python3 test/runner/e2e_runner.py --tests-dir build --dataset-dir env/datasets/Dataset
python3 test/runner/e2e_runner.py --tests-dir build --dataset-dir test/env/datasets/Dataset
```

### GTest arguments

`--gtest_filter` is handled by the runner itself: it decides which binaries and which tests get scheduled, so it must be passed to the runner rather than to the binaries.

```bash
python3 test/runner/e2e_runner.py --gtest_filter=CoreTest.listContextUsers
python3 test/runner/e2e_runner.py --gtest_filter=CoreTest.*
```

Any other argument is forwarded verbatim to each test executable:

```bash
python3 test/runner/e2e_runner.py -- --gtest_repeat=2 --gtest_break_on_failure
```

`--ini_file_path`/`-i` and `--bridge_url`/`-b` are managed by the runner and rejected if you try to forward them: each test is pointed at its own Bridge.

## Datasets

A dataset is a snapshot of a seeded Bridge. The runner recreates that state for every test, from:

| Entry | Purpose |
|-------|---------|
| `ServerData.ini` | Solution, context ids, API key, and user keys the tests log in with |
| `mongo_collections/*.json` | Collections inserted into the fresh per-test database |
| `storage/` | Files copied into the Bridge container |
| `migration.json` | Pins the Bridge to the migration the dataset was created at |

This repository ships a working dataset in `env/datasets/Dataset`. Create new ones with [`scripts/dataset.sh`](../scripts/README.md#datasets), which wraps the tool in `env/create_dataset/`:

```bash
./env/create_dataset/main.sh --help     # advanced options
```

Without a name, a dataset is created as `env/datasets/Dataset_YYYY-mm-dd_HH-MM`.

When you change the data the server produces, generating a new dataset is recommended — but keep running the tests against the older ones too, to check backward compatibility.
