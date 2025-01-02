#!/bin/bash
cd ..
mkdir -p build
conan install . --build=missing 
cd build
source Release/generators/conanbuild.sh
cmake .. -G "Unix Makefiles" -DCMAKE_TOOLCHAIN_FILE=Release/generators/conan_toolchain.cmake \
        -DCMAKE_POLICY_DEFAULT_CMP0091=NEW \
        -DCMAKE_BUILD_TYPE=Release -DPRIVMX_CONAN=ON -DPRIVMX_DRIVER_NET=ON -DPRIVMX_DRIVER_CRYPTO=ON -DPRIVMX_BUILD_ENDPOINT=ON \
        -DPRIVMX_BUILD_CLI=OFF -DPRIVMX_BUILD_DEBUG_APPS=ON
cmake --build . -- -j20
source Release/generators/deactivate_conanbuild.sh
source Release/generators/conanrun.sh
