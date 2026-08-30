#!/usr/bin/env bash
#
# build.sh -- one-step build for the Nim binding: builds libitb.so,
# type-checks the binding sources, and compiles the eitb CLI binary.
# Prerequisites (Go, Nim 2.x) must be installed separately; see
# README.md "Prerequisites" section.
#
# Usage:
#   ./build.sh             # default build (full asm stack)
#   ./build.sh --noitbasm  # opt out of ITB's chain-absorb asm
#                          # (use on hosts without AVX-512+VL)

set -eu
set -o pipefail

cd "$(dirname "$0")"
REPO_ROOT="$(cd ../.. && pwd)"

TAGS=()
case "${1:-}" in
    --noitbasm) TAGS=(-tags=noitbasm); shift;;
    -h|--help)  echo "usage: $0 [--noitbasm]"; exit 0;;
    "")         ;;
    *)          echo "unknown option: $1" >&2; exit 2;;
esac

cd "$REPO_ROOT"
echo "==> building libitb.so${TAGS:+ (with ${TAGS[*]})}"
go build -trimpath "${TAGS[@]}" -buildmode=c-shared \
    -o dist/linux-amd64/libitb.so ./cmd/cshared

cd "$REPO_ROOT/bindings/nim"
echo "==> type-checking the itb Nim sources"
nim check --hints:off src/itb.nim

echo "==> compiling the eitb CLI"
nim c -d:release --hints:off --outdir:eitb/build \
    --nimcache:eitb/build/nimcache eitb/itb_eitb.nim

echo "==> ready: ./run_tests.sh"
