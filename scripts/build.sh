#!/bin/bash
set -e
cd "$(dirname "${BASH_SOURCE[0]}")/.."
mkdir -p ./build
BUILD_TYPE="Debug"
# GCC 15+ defaults to -std=gnu23, which rejects the K&R declarations in legacy C deps (termcap)
conan install conanfile-dev.py --output-folder=build --build=missing -s build_type=$BUILD_TYPE \
       -o "&:with_webrtc=False" -o "&:with_cli=False" -o "&:with_tests=True" \
       -c 'tools.build:cflags=["-std=gnu17"]'
cd build
GENERATORS_DIR="build/$BUILD_TYPE/generators"

source $GENERATORS_DIR/conanbuild.sh
cmake .. -G "Unix Makefiles" -DCMAKE_TOOLCHAIN_FILE=$GENERATORS_DIR/conan_toolchain.cmake \
       -DCMAKE_POLICY_DEFAULT_CMP0091=NEW  -DCMAKE_BUILD_TYPE=$BUILD_TYPE \
       -DPRIVMX_BUILD_DEBUG_APPS=OFF \
       -DPRIVMX_BUILD_ENDPOINT_INTERFACE=ON \
       -DPRIVMX_ENABLE_TESTS_E2E=ON
cmake --build . --parallel "$(nproc)"
source $GENERATORS_DIR/deactivate_conanbuild.sh