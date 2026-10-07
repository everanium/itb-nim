#!/usr/bin/env bash
#
# Fleet entry point for the loop stress harness of the Nim binding:
# rebuilds the utility when a source is newer than the binary (a no-op
# otherwise; libitb3.so is assumed built by build.sh) and execs it with
# every argument passed through.
#
# The compiler output is captured rather than discarded: Nim reports
# hints and warnings on stderr, and a redirect of stdout alone would
# let its lines join the utility's own output. Nothing is printed
# unless the build fails, in which case everything it said is.
#
# Usage:
#   ./run_loop.sh --duration 2m --shape both

set -eu
set -o pipefail

cd "$(dirname "$0")"

stale=0
if [ ! -x loop/loop ]; then
    stale=1
else
    for src in loop/*.nim src/itb3.nim src/itb3/*.nim; do
        if [ "$src" -nt loop/loop ]; then
            stale=1
            break
        fi
    done
fi

if [ "$stale" = 1 ]; then
    if ! build_output="$(nim c -d:release -d:gcAtomicArc --hints:off \
        --nimcache:loop/nimcache -o:loop/loop loop/main.nim 2>&1)"; then
        printf '%s\n' "$build_output" >&2
        exit 1
    fi
fi

exec ./loop/loop "$@"
