#!/bin/bash
cd "$(dirname "${BASH_SOURCE[0]}")/.."
doxygen ./doxygen.config
mkdir -p ./doc/json
doxybook --input ./doc/xml --output ./doc/json --json