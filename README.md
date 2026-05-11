## PrivMX Endpoint
Programming library used by applications and devices which are the ends of PrivMX secure communication channels. It encrypts and decrypts data, manages network connections and provides a functional API, allowing the applications to build their E2EE communication channels based on a few universal, client-side encrypted tools: Threads, Stores, and Inboxes.

PrivMX Endpoint is a modular, low-level library written in C++, ready to be configured and used on any device (including IoT, VR + more) and any operating system.

## Key Benefits
 - **Modular and Flexible**: PrivMX Endpoint is designed to allow developers to easily configure and integrate it into any device or operating system. Developed in C++, PrivMX Endpoint is designed to be **platform-independent**, making it suitable for a wide range of devices, including IoT, VR, and more. Wrappers for other languages (like JavaScript, Java, Kotlin, Swift, C#) can be found in our other [repositories](https://github.com/orgs/simplito/repositories?q=privmx).
    
- **Secure Communication**: PrivMX Endpoint encrypts and decrypts data, ensuring secure communication between applications and devices. It leverages the user's private key to establish the **end-to-end encrypted** channels.
    
- **Simplified Development**: The library provides a functional API that allows developers to focus on building their core application features. Together with PrivMX Bridge (which serves as the backend), you receive a **full-fledged solution** allowing for rapid development of secure end-to-end encrypted applications across all major platforms.

## PrivMX Bridge
To use PrivMX to develop your apps, you also need PrivMX Bridge. It is a **zero-knowledge server** that intermediates in the **transfer of encrypted data** and notifications between PrivMX Endpoints and **stores encrypted data**. See how to install and use PrivMX Bridge in its [repository](https://github.com/simplito/privmx-bridge).
## Containers
PrivMX enables communication through **text messages**, **secure file storage** and **real-time data streaming**. **PrivMX Containers** are sets of events and APIs designed to setup your app for specific types of communication.
- **Thread** –  a structured communication tool used for **message-based communication.**
- **Store** –  data storage and communication tool used for **file exchange and management**.
- **Inbox** – a communication tool used for **one-way communication with external users**.

## Building

### Prerequisites

- CMake ≥ 3.10.2
- C++17-capable compiler (GCC or Clang)
- [Conan 2.x](https://conan.io/) (recommended) — or manually provided pre-built libraries

The library always uses the driver backends (`privmxdrvcrypto`, `privmxdrvecc`, `privmxdrvnet`) for crypto and networking. These are resolved automatically by Conan or must be supplied manually when building without it.

### 1. Building with Conan (Recommended)

Conan resolves all dependencies automatically: `poco`, `openssl`, `gmp`, `pson`, `privmxdrvcrypto`, `privmxdrvecc`, `privmxdrvnet`, `gtest`.

**Quick start:**
```bash
./build.sh
```

**Manual steps:**
```bash
mkdir -p ./build
conan install . --output-folder=build --build=missing -s build_type=Debug
cd build
source build/Debug/generators/conanbuild.sh
cmake .. -G "Unix Makefiles" \
  -DCMAKE_TOOLCHAIN_FILE=build/Debug/generators/conan_toolchain.cmake \
  -DCMAKE_BUILD_TYPE=Debug \
  -DPRIVMX_CONAN=ON \
  -DPRIVMX_ENABLE_TESTS=ON
cmake --build . -- -j$(nproc)
source build/Debug/generators/deactivate_conanbuild.sh
```

### 2. Building without Conan (find_package)

When Conan is not available, CMake will attempt to locate the following libraries via `find_package`:

| Library | Version |
|---------|---------|
| poco | 1.13.2 |
| pson | 1.0.7 |
| openssl | ≥ 3.0, < 3.1 |
| gmp | 6.2.1 |
| privmxdrvcrypto | 1.0.3 |
| privmxdrvecc | 1.0.2 |
| privmxdrvnet | 1.0.3 |
| gtest | ≥ 1.15.0 *(optional, needed for tests)* |
| readline | ≥ 8.2.0 *(optional, needed for CLI)* |
| libwebrtc | m125 *(optional, needed for WebRTC streaming)* |

```bash
mkdir -p build && cd build
cmake .. \
  -DCMAKE_BUILD_TYPE=Release \
  -DPRIVMX_CONAN=OFF
cmake --build . -- -j$(nproc)
```

### CMake Options

| Option | Default | Description |
|--------|---------|-------------|
| `PRIVMX_CONAN` | ON | Must be ON when using Conan toolchain |
| `BUILD_SHARED_LIBS` | ON | Build shared (`.so`) vs. static (`.a`) library |
| `PRIVMX_IMPORTED_LIBRARIES` | OFF | Point to pre-built libs instead of using `find_package` |
| `PRIVMX_ENABLE_TESTS` | OFF | Build unit tests |
| `PRIVMX_ENABLE_TESTS_E2E` | OFF | Build E2E integration tests |
| `PRIVMX_BUILD_CLI` | OFF | Build `privmxcli` command-line tool |
| `PRIVMX_EMSCRIPTEN` | OFF | WebAssembly/Emscripten build |
| `PRIVMX_BUILD_WITH_WEBRTC` | OFF | Enable WebRTC support for real-time streaming |

#### Logger Options (require `PRIVMX_BUILD_LOGGER=ON`)

| Option | Default | Description |
|--------|---------|-------------|
| `PRIVMX_BUILD_LOGGER` | OFF | Enable the logging subsystem |
| `PRIVMX_ENABLE_LOGGER_TIMER` | OFF | Include timing info in log entries |
| `PRIVMX_LOGGER_LEVEL` | 3 | Verbosity level (e.g. `6` for All log levels) |
| `PRIVMX_LOGGER_OUTPUT_INCLUDE_TIMESTAMP` | OFF | Prepend timestamp to each log line |
| `PRIVMX_LOGGER_OUTPUT_INCLUDE_THREADID` | OFF | Prepend thread ID to each log line |
| `PRIVMX_LOGGER_OUTPUT_STDOUT` | OFF | Log to stdout |
| `PRIVMX_LOGGER_OUTPUT_STDERR` | OFF | Log to stderr |
| `PRIVMX_LOGGER_OUTPUT_FILE` | OFF | Log to a file |
| `PRIVMX_LOGGER_OUTPUT_FILE_PATH` | — | Path for the log file (e.g. `output.log`) |

## Resources

- [PrivMX Documentation](https://docs.privmx.dev/)
- [API Reference](https://docs.privmx.dev/docs/latest/start/api-reference)
- [other PrivMX repositories](https://github.com/orgs/simplito/repositories?q=privmx) (libraries and wrappers)

## CI/CD

This repository uses GitHub Actions for automated testing, documentation builds, and releases.

- `Tests E2E` runs on pushes to `main` and on pull requests targeting `main` or `devel`.
- `Build Doxygen Docs` can be started manually and also runs on every pushed tag.
- `Deploy Release` creates a production GitHub release for tags such as `v1.2.3` when the tagged commit is reachable from `main`.
- `Deploy Release` creates a GitHub pre-release for tags such as `v1.2.3-rc1` when the tagged commit is reachable from an `rc-*` branch.

For the detailed release procedure, tag naming rules, and safe testing guidance, see [RELEASING.md](RELEASING.md).

## License
PrivMX Free License
