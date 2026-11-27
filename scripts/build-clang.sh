#!/bin/bash
cd "$(dirname "${BASH_SOURCE[0]}")/.."
mkdir -p ./build
BUILD_TYPE="Debug"
# -c tools.build:cflags: Clang 20+ defaults to -std=gnu23, which rejects the K&R declarations in
#   legacy C deps (termcap).
# -s compiler.cppstd=20: pmx-crypto's recipe calls check_min_cppstd(20), and a detected profile
#   settles on gnu17.
conan install conanfile-dev.py --output-folder=build --build=missing -s build_type=$BUILD_TYPE \
       -s compiler.cppstd=20 \
       -o "&:with_webrtc=False" -o "&:with_cli=False" -o "&:with_tests=True" \
       -c 'tools.build:cflags=["-std=gnu17"]'
cd build

GENERATORS_DIR="build/$BUILD_TYPE/generators"

source $GENERATORS_DIR/conanbuild.sh
cmake .. -G "Unix Makefiles" -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_TOOLCHAIN_FILE=$GENERATORS_DIR/conan_toolchain.cmake \
       -DCMAKE_POLICY_DEFAULT_CMP0091=NEW  -DCMAKE_BUILD_TYPE=$BUILD_TYPE \
       -DPRIVMX_BUILD_DEBUG_APPS=OFF \
       -DPRIVMX_BUILD_ENDPOINT_INTERFACE=ON \
       -DPRIVMX_ENABLE_TESTS_E2E=ON
cmake --build . --parallel "$(nproc)"
source $GENERATORS_DIR/deactivate_conanbuild.sh
source $GENERATORS_DIR/conanrun.sh
