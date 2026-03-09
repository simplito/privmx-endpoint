# API Reference Documentation

This directory contains the configuration and template for the Doxygen documentation generator.

## Requirements

Doxygen version 1.16.1 is required to build the documentation.

## Building Documentation

Run the `./build-docs.sh` command to build the documentation.

The script automatically detects the version (via `git describe --tags`), which is then included in the documentation and used as the name for the output directory: `html/<version>`.

## Adding New Modules

In the `Doxyfile`, add the appropriate paths to the following values: `STRIP_FROM_PATH`, `STRIP_FROM_INC_PATH`, and `INPUT`.

## Editing Home Page

The content of the home page is located in the `template/index.md` file.
