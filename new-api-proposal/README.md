## PrivMX Endpoint new API proposal

This is a working version of the new API proposal for PrivMX Endpoint

## Building

### Prerequisites

- CMake ≥ 3.12
- C++20-capable compiler (tested with GCC)
- [Conan 2.x](https://conan.io/) (recommended) — or manually provided pre-built libraries

### 1. Building with Conan (Recommended)

Conan resolves all dependencies automatically: `poco`, `openssl`, `gmp`, `pson`, `privmxdrvnet`, `gtest`.

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
make .. -G "Unix Makefiles" \
       -DCMAKE_TOOLCHAIN_FILE=build/Debug/generators/conan_toolchain.cmake \
       -DCMAKE_POLICY_DEFAULT_CMP0091=NEW  -DCMAKE_BUILD_TYPE=Debug
cmake --build . -- -j20
source build/Debug/generators/deactivate_conanbuild.sh
```

### 2. Testing with gtest

**Quick start:**
```bash
cd build
ctest
```
