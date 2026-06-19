# privmxBenchmark

Performance-measurement tools for the PrivMX Endpoint container APIs (Threads, Stores, Inboxes) and the Crypto API. They connect to a running **PrivMX Bridge** instance and time real end-to-end operations (encryption + network round-trips included).

This directory builds **two** executables:

| Executable | Purpose |
|------------|---------|
| `privmxBenchmark` | Runs **one** scenario (module + operation group) chosen on the command line, either a fixed number of times or for a fixed duration, and prints aggregate timing. |
| `privmxPerformanceTester` | Runs a **fixed suite** of scenarios (each repeated 100×) and prints a table of min/max/avg times. No command-line arguments. |

Both require a live Bridge to connect to and a user identity supplied through an INI file.

---

## Building

The benchmark is **not** built by default. Enable it with `-DPRIVMX_BUILD_BENCHMARK=ON` (it also requires `PRIVMX_BUILD_ENDPOINT_ENDPOINT=ON`, which is on by default).

Starting from the standard build (see the repo `build.sh`), add the flag to the CMake configure step:

```bash
cmake .. -G "Unix Makefiles" \
  -DCMAKE_TOOLCHAIN_FILE=build/Debug/generators/conan_toolchain.cmake \
  -DCMAKE_BUILD_TYPE=Debug \
  -DPRIVMX_CONAN=ON \
  -DPRIVMX_DRIVER_NET=ON \
  -DPRIVMX_DRIVER_CRYPTO=ON \
  -DPRIVMX_BUILD_BENCHMARK=ON
cmake --build . -- -j$(nproc)
```

The binaries are produced at:

```
build/endpoint/programs/benchmark/privmxBenchmark
build/endpoint/programs/benchmark/privmxPerformanceTester
```

(exact path depends on your build directory layout).

---

## Configuration

Both tools read the connection credentials from an **INI file** whose path is given by the `INI_FILE_PATH` environment variable. The file must contain a `[Login]` section:

```ini
[Login]
user_1_privKey = Kx9ftJtfa4Af941f9jYR44dKxv9uWMxkJBk3XgdSYy6M5i6zcXxS
user_1_pubKey  = 6GdpXA9ro6hDabKKFsnuq4EJ1NYNLqsnLzTLCAyL55FMSk8xSM
user_1_id      = user_1
solutionId     = a37a4e8f-8034-441e-8da8-d0d1744a228e
instanceUrl    = http://localhost/
```

The repo ships a ready-made dataset you can point at:
`test/test_env/create_dataset/Dataset/ServerData.ini` (used by the E2E tests; start the Bridge with `cd test && docker compose up -d`).

### Environment variables

| Variable | Required | Meaning |
|----------|----------|---------|
| `INI_FILE_PATH` | **yes** | Filesystem path to the INI file described above. |
| `PLATFORM_URL` | no | If set, overrides `Login.instanceUrl`; the tools connect to `http://<PLATFORM_URL>/`. Useful when the Bridge URL is allocated dynamically. |

```bash
source build/build/Debug/generators/conanrun.sh   # so the shared libs are found
export INI_FILE_PATH="$PWD/test/test_env/create_dataset/Dataset/ServerData.ini"
```

The tools always connect as `user_1` and run against the **first** Context returned by `listContexts`. Make sure that user has access to at least one Context.

---

## `privmxBenchmark`

```
privmxBenchmark <mode> <duration> <module> <group>
```

| Argument | Values | Meaning |
|----------|--------|---------|
| `mode` | `Count` (aliases: `count`, `N-times`, `n-times`, `0`) | Run the scenario exactly `<duration>` times. |
|        | `Timeout` (aliases: `timeout`, `1`) | Run the scenario repeatedly for `<duration>` **seconds**. |
| `duration` | integer | Iteration count (Count mode) or number of seconds (Timeout mode). |
| `module` | `thread`, `store`, `inbox`, `crypto`, `kvdb`, `event` (capitalized forms also accepted) | Which API to exercise. |
| `group` | integer — decimal or `0x`-prefixed hex | Which operation group to run (see tables below). |

> The `group` accepts either a plain decimal value (e.g. `65541`) or the matching hex form with a `0x`/`0X` prefix (e.g. `0x10005`). Hex without the prefix is treated as decimal. The group ids are laid out as `0x00MMnnnn`, so the hex form is usually the easier one to read.

### Output

```
Total time - 12.34s
Total exec - 100
Avarage time - 123.4ms
Min single exec time - 110.2ms
Max single exec time - 180.7ms
```

Each "exec" is one full pass of the chosen group (which may chain several API calls — see the tables). Some scenarios create resources up-front in a prepare phase; that setup time is **not** included in the measured loop.

### Examples

```bash
# Send 100 messages to a freshly created Thread, report timing
privmxBenchmark Count 100 thread 65536
# ...same scenario, group given in hex
privmxBenchmark Count 100 thread 0x10000

# Hammer "get message" for 30 seconds
privmxBenchmark Timeout 30 thread 131072

# Create+get+delete a Store, 50 times
privmxBenchmark Count 50 store 2

# Encrypt+decrypt a 1 MB buffer, 200 times (no Bridge calls in the loop)
privmxBenchmark Count 200 crypto 5

# Set 100 KVDB entries (unique key each time) in a freshly created KVDB
privmxBenchmark Count 100 kvdb 0x10000

# Emit 100 custom events
privmxBenchmark Count 100 event 0
```

### Operation groups

The group id encodes a sub-category in its high bits: `0x0000xxxx` = container CRUD, `0x0001xxxx` = item / file / entry operations, `0x0002xxxx` = read-back operations. Decimal values are what you pass on the command line.

#### `thread`

| group (dec) | hex | Operation(s) per iteration |
|---|---|---|
| 0 | 0x00000000 | createThread |
| 1 | 0x00000001 | createThread → getThread |
| 2 | 0x00000002 | createThread → getThread → deleteThread |
| 3 | 0x00000003 | createThread → listThreads (limit 100) |
| 4 | 0x00000004 | createThread → updateThread → getThread |
| 65536 | 0x00010000 | sendMessage |
| 65537 | 0x00010001 | sendMessage → getMessage |
| 65538 | 0x00010002 | sendMessage → getMessage → deleteMessage |
| 65539 | 0x00010003 | sendMessage → listMessages (limit 100) |
| 65540 | 0x00010004 | sendMessage → updateMessage → getMessage |
| 65541 | 0x00010005 | sendMessage, 1 KB payload |
| 65542 | 0x00010006 | sendMessage, 4 KB payload |
| 131072 | 0x00020000 | getMessage |
| 131073 | 0x00020001 | getMessage (message prepared with 1 KB payload) |
| 131074 | 0x00020002 | getMessage (message prepared with 4 KB payload) |

#### `store`

| group (dec) | hex | Operation(s) per iteration |
|---|---|---|
| 0 | 0x00000000 | createStore |
| 1 | 0x00000001 | createStore → getStore |
| 2 | 0x00000002 | createStore → getStore → deleteStore |
| 3 | 0x00000003 | createStore → listStores (limit 100) |
| 4 | 0x00000004 | createStore → updateStore → getStore |
| 65536 | 0x00010000 | createFile → writeToFile → closeFile (small) |
| 65537 | 0x00010001 | createFile → write → close → getFile |
| 65538 | 0x00010002 | createFile → write → close → getFile → deleteFile |
| 65539 | 0x00010003 | createFile → write → close → listFiles (limit 100) |
| 65540 | 0x00010004 | createFile → write → close → updateFile → write → close → getFile |
| 65541 | 0x00010005 | createFile + write, 1 MB |
| 65542 | 0x00010006 | createFile + write, 8 MB |
| 131072 | 0x00020000 | getFile → openFile → readFromFile |
| 131073 | 0x00020001 | getFile/read (file prepared at 1 MB) |
| 131074 | 0x00020002 | getFile/read (file prepared at 8 MB) |

#### `inbox`

| group (dec) | hex | Operation(s) per iteration |
|---|---|---|
| 0 | 0x00000000 | createInbox |
| 1 | 0x00000001 | createInbox → getInbox |
| 2 | 0x00000002 | createInbox → getInbox → deleteInbox |
| 3 | 0x00000003 | createInbox → listInboxes (limit 100) |
| 4 | 0x00000004 | createInbox → updateInbox → getInbox |
| 65536 | 0x00010000 | prepareEntry → sendEntry (no files) |
| 65537 | 0x00010001 | prepareEntry → sendEntry → listEntries (limit 1) |
| 65538 | 0x00010002 | prepareEntry → sendEntry → listEntries → deleteEntry |
| 65539 | 0x00010003 | prepareEntry → sendEntry → listEntries (limit 100) |
| 65540 | 0x00010004 | prepareEntry → sendEntry → listEntries → readEntry |
| 65541 | 0x00010005 | sendEntry with 5 empty files |
| 65542 | 0x00010006 | sendEntry with 5 files, 1 MB each |
| 131072 | 0x00020000 | readEntry (entry prepared with no files) |
| 131073 | 0x00020001 | readEntry (entry prepared with 5 empty files) |
| 131074 | 0x00020002 | readEntry (entry prepared with 5 files, 1 MB each) |

#### `crypto`

Pure local crypto — no Bridge calls in the measured loop.

| group (dec) | hex | Operation per iteration |
|---|---|---|
| 0 | 0x00000000 | encrypt (symmetric), 1 KB |
| 1 | 0x00000001 | encrypt + decrypt, 1 KB |
| 2 | 0x00000002 | encrypt, 32 KB |
| 3 | 0x00000003 | encrypt + decrypt, 32 KB |
| 4 | 0x00000004 | encrypt, 1 MB |
| 5 | 0x00000005 | encrypt + decrypt, 1 MB |

#### `kvdb`

| group (dec) | hex | Operation(s) per iteration |
|---|---|---|
| 0 | 0x00000000 | createKvdb |
| 1 | 0x00000001 | createKvdb → getKvdb |
| 2 | 0x00000002 | createKvdb → getKvdb → deleteKvdb |
| 3 | 0x00000003 | createKvdb → listKvdbs (limit 100) |
| 4 | 0x00000004 | createKvdb → updateKvdb → getKvdb |
| 65536 | 0x00010000 | setEntry (unique key) |
| 65537 | 0x00010001 | setEntry → getEntry |
| 65538 | 0x00010002 | setEntry → getEntry → deleteEntry |
| 65539 | 0x00010003 | setEntry → listEntries (limit 100) |
| 65540 | 0x00010004 | setEntry → hasEntry |
| 65541 | 0x00010005 | setEntry, 1 KB value |
| 65542 | 0x00010006 | setEntry → listEntriesKeys (limit 100) |
| 131072 | 0x00020000 | getEntry (entry prepared up-front) |

Entry-writing groups generate a fresh key each iteration, so repeated runs do not collide.

#### `event`

Custom (contextual) events. `emitEvent` and `subscribeFor`/`unsubscribeFrom` are round-trips to the Bridge; `buildSubscriptionQuery` is local-only.

| group (dec) | hex | Operation(s) per iteration |
|---|---|---|
| 0 | 0x00000000 | emitEvent (small payload) |
| 1 | 0x00000001 | emitEvent, 1 KB payload |
| 65536 | 0x00010000 | subscribeFor → unsubscribeFrom |
| 65537 | 0x00010001 | buildSubscriptionQuery (local only) |

Events are emitted on the `benchmark` channel to the connected user; `buildSubscriptionQuery` uses selector `CONTEXT_ID`.

---

## `privmxPerformanceTester`

A self-contained suite that creates one Thread / Store / Inbox up-front and then times a fixed set of operations, each repeated 100 times. It takes **no arguments** — just the `INI_FILE_PATH` (and optional `PLATFORM_URL`) environment.

```bash
export INI_FILE_PATH="$PWD/test/test_env/create_dataset/Dataset/ServerData.ini"
build/endpoint/programs/benchmark/privmxPerformanceTester
```

It prints rows of `|label|min|max|avg` (milliseconds) for: `sendMessage`, `getMessage`, `readFromFile`, `writeToFile` (1 MB), `readEntry`, and `sendEntry` (1 MB inbox file).

---

## Helper scripts

- **`env.sh`** — convenience file to `export INSTANCE_SERVER` / `INI_FILE_PATH`. Fill in the commented lines for your setup; `createTable.sh` sources it.
- **`createTable.sh`** — drives `privmxBenchmark` across a representative set of thread/store/inbox groups. It expects an `INSTANCE_SERVER` that hands out a temporary Bridge instance via `GET /getInstance` (and releases it via `/releaseInstance`), exporting the allocated URL as `PLATFORM_URL` for each run. Adjust `INSTANCE_SERVER`/`BUILD_PATH` for your environment.

---

## Notes & caveats

- The tools connect once as `user_1` and reuse a single connection for the whole run.
- Container/file/entry resources created during runs are generally **not** cleaned up (except groups that explicitly include a delete step). Expect the target Context to accumulate objects; use a disposable Bridge instance for repeated runs.
- `privmxBenchmark` divides total time by the executed count to compute the average, so a `Count`/`duration` of `0` is not meaningful.
- Timing covers the full client path: serialization, encryption, transport, and server processing — it is not a micro-benchmark of any single layer (except the `crypto` module, which stays local).
