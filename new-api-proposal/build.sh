#!/bin/bash
set -e
mkdir -p ./build
BUILD_TYPE="Debug"
conan install . --output-folder=build --build=missing -s build_type=$BUILD_TYPE
cd build
GENERATORS_DIR="build/$BUILD_TYPE/generators"

source $GENERATORS_DIR/conanbuild.sh
cmake .. -G "Unix Makefiles" \
       -DCMAKE_TOOLCHAIN_FILE=$GENERATORS_DIR/conan_toolchain.cmake \
       -DCMAKE_POLICY_DEFAULT_CMP0091=NEW  -DCMAKE_BUILD_TYPE=$BUILD_TYPE
#cmake .. -G "Unix Makefiles" \
#       -DCMAKE_C_COMPILER=gcc-12 -DCMAKE_CXX_COMPILER=cpp-12 \
#       -DCMAKE_TOOLCHAIN_FILE=$GENERATORS_DIR/conan_toolchain.cmake \
#       -DCMAKE_POLICY_DEFAULT_CMP0091=NEW  -DCMAKE_BUILD_TYPE=$BUILD_TYPE
cmake --build . -- -j20
source $GENERATORS_DIR/deactivate_conanbuild.sh