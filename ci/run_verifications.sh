#!/bin/sh
# POSIX verification runner (Linux / macOS): T5 evidence without any third-party dependency.
# Usage: sh ci/run_verifications.sh
set -e
cd "$(dirname "$0")/.."
python3 scripts/run_harness.py
