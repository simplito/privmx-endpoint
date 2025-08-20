#!/bin/bash
BUILD_TYPE="Debug"
mkdir -p ./build
conan install . --output-folder=build -s build_type=$BUILD_TYPE --build=missing
cd build

GENERATORS_DIR="build/$BUILD_TYPE/generators"

source $GENERATORS_DIR/conanbuild.sh
cmake .. -G "Unix Makefiles" -DCMAKE_TOOLCHAIN_FILE=$GENERATORS_DIR/conan_toolchain.cmake \
       -DCMAKE_POLICY_DEFAULT_CMP0091=NEW -DCMAKE_BUILD_TYPE=$BUILD_TYPE \
       -DPRIVMX_DRIVER_NET=ON \
       -DPRIVMX_DRIVER_CRYPTO=ON \
       -DPRIVMX_CONAN=ON \
       -DPRIVMX_BUILD_CLI=OFF \
       -DPRIVMX_BUILD_DEBUG_APPS=OFF \
       -DPRIVMX_BUILD_ENDPOINT_INTERFACE=ON \
       -DPRIVMX_ENABLE_TESTS=OFF \
       -DPRIVMX_ENABLE_TESTS_E2E=OFF \
       -DPRIVMX_BUILD_DEBUG=OFF \
       -DPRIVMX_BUILD_STREAM_TESTING=ON \
       -DPRIVMX_BUILD_WITH_WEBRTC=ON
cmake --build . -- -j20
source $GENERATORS_DIR/deactivate_conanbuild.sh
source $GENERATORS_DIR/conanrun.sh
