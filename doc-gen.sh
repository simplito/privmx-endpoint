#!/bin/bash
doxygen ./doxygen.config
mkdir -p ./doc/json
doxybook --input ./doc/xml --output ./doc/json --json