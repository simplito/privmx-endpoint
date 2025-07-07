#!/bin/bash
mkdir -p ./build
conan install . --output-folder=build --build=missing
cd build

GENERATORS_DIR="build/Release/generators"

source $GENERATORS_DIR/conanbuild.sh
cmake .. -G "Unix Makefiles" -DCMAKE_TOOLCHAIN_FILE=$GENERATORS_DIR/conan_toolchain.cmake \
       -DCMAKE_POLICY_DEFAULT_CMP0091=NEW  -DCMAKE_BUILD_TYPE=Release \
       -DPRIVMX_DRIVER_NET=ON \
       -DPRIVMX_DRIVER_CRYPTO=ON \
       -DPRIVMX_CONAN=ON \
       -DPRIVMX_BUILD_CLI=OFF \
       -DPRIVMX_BUILD_DEBUG_APPS=OFF \
       -DPRIVMX_BUILD_ENDPOINT_INTERFACE=ON \
       -DPRIVMX_ENABLE_TESTS=ON \
       -DPRIVMX_ENABLE_TESTS_E2E=ON \
       -DPRIVMX_BUILD_DEBUG=OFF
cmake --build . -- -j20
source $GENERATORS_DIR/deactivate_conanbuild.sh
source $GENERATORS_DIR/conanrun.sh
