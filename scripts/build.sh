#!/bin/bash
set -e
cd "$(dirname "${BASH_SOURCE[0]}")/.."
mkdir -p ./build
BUILD_TYPE="Debug"
# -c tools.build:cflags: GCC 15+ defaults to -std=gnu23, which rejects the K&R declarations in
#   legacy C deps (termcap).
# -s compiler.cppstd=20: pmx-crypto's recipe calls check_min_cppstd(20) and `conan profile detect`
#   settles on gnu17, so without this the install fails before anything is built. The library itself
#   has been C++20 since CMakeLists.txt set CMAKE_CXX_STANDARD 20 — this only tells Conan so.
conan install conanfile-dev.py --output-folder=build --build=missing -s build_type=$BUILD_TYPE \
       -s compiler.cppstd=20 \
       -o "&:with_webrtc=False" -o "&:with_cli=False" -o "&:with_tests=True" \
       -c 'tools.build:cflags=["-std=gnu17"]'
cd build
GENERATORS_DIR="build/$BUILD_TYPE/generators"

source $GENERATORS_DIR/conanbuild.sh
# PRIVMX_CONAN, PRIVMX_DRIVER_NET, PRIVMX_BUILD_CLI and PRIVMX_ENABLE_TESTS are no longer passed
# here: conanfile-dev.py sets them through the toolchain, from its own options.
cmake .. -G "Unix Makefiles" -DCMAKE_TOOLCHAIN_FILE=$GENERATORS_DIR/conan_toolchain.cmake \
       -DCMAKE_POLICY_DEFAULT_CMP0091=NEW  -DCMAKE_BUILD_TYPE=$BUILD_TYPE \
       -DPRIVMX_BUILD_DEBUG_APPS=OFF \
       -DPRIVMX_BUILD_ENDPOINT_INTERFACE=ON \
       -DPRIVMX_ENABLE_TESTS_E2E=ON \
       -DPRIVMX_DEFAULT_CRYPTO_SUITE=aes256gcm-sha256 \
       -DPRIVMX_DEFAULT_FILE_CIPHER=aes256cbc-hmac-sha256 \
       -DPRIVMX_DEFAULT_KEY_ALGORITHM=ed25519
cmake --build . --parallel "$(nproc)"
source $GENERATORS_DIR/deactivate_conanbuild.sh
