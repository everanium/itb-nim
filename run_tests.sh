#!/usr/bin/env bash
#
# run_tests.sh -- one-step test runner for the Nim binding. Builds
# libitb3.so via build.sh, points ITB_LIBITB3_PATH at the freshly-built
# shared library, then compiles and runs the unittest suite.
# Positional arguments are forwarded to the test binary (e.g. a
# single test via `./run_tests.sh "message round trip"`).
#
# Usage:
#   ./run_tests.sh                         # full suite
#   ./run_tests.sh "stream round trip"     # one test

set -eu
set -o pipefail

cd "$(dirname "$0")"
REPO_ROOT="$(cd ../.. && pwd)"
DIST_DIR="$REPO_ROOT/dist/linux-amd64"

./build.sh

export ITB_LIBITB3_PATH="$DIST_DIR/libitb3.so"

nim c --hints:off --outdir:tests/build \
    --nimcache:tests/build/nimcache tests/tconcept.nim
exec ./tests/build/tconcept "$@"
