#!/bin/bash
#
# GmSSL-Python Test Runner
#
# "Talk is cheap. Show me the code." - Linus Torvalds
#
# This script runs tests with the correct environment setup.

set -e

# Activate virtual environment
source .venv/bin/activate

# Set library path for GmSSL
export DYLD_LIBRARY_PATH=./gm/lib

# Run pytest with verbose output
pytest tests/ -v "$@"

