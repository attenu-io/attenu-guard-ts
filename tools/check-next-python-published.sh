#!/usr/bin/env bash
# tools/check-next-python-published.sh <package> <version-prefix>
#
# Prints "true" or "false" to stdout: whether PyPI's index for <package> lists any version
# starting with <version-prefix> (e.g. "0.10." matches "0.10.0", "0.10.3", ...). Used by
# .github/workflows/ci.yml's `interop-next` job to decide whether the next Python minor is
# published yet, without hand-widening a version pin every time it ships.
#
# Release-gate correction (MEDIUM): the version this script replaces ran the whole query and
# match INSIDE one `if PIPE | grep -q ...; then ... else ...; fi` compound command. Two problems
# at once: (1) a compound `if` condition is exempt from `set -e` by design (that is what lets
# `if some-command-that-may-fail; then` work at all), so a failing query never stopped the
# script; (2) without `pipefail`, a pipeline's exit status is its LAST command's only, so even a
# non-zero exit from the query itself was invisible to the `if` -- `grep -q` just saw empty
# input, found no match, and the `else` branch printed `published=false` with the step still
# exiting 0. Reproduced directly: a simulated exit 42 from the query flowed straight through to
# `published=false`, indistinguishable from "0.10.x genuinely does not exist yet" -- a PyPI
# outage silently read as a fact about what has been released. See
# `.github/workflows/ci.yml`'s probe step, which runs this exact failure on every CI run to keep
# it from recurring.
#
# Fixed by separating the two concerns: capture the query's own exit code FIRST, in its own
# statement (not inside an `if` compound), and fail this whole script -- loudly, non-zero,
# without printing "false" at all -- before ever reaching the match logic.
set -eu

package="$1"
prefix="$2"

set +e
versions_output=$(python3 -m pip index versions "$package" 2>&1)
rc=$?
set -e

if [ "$rc" -ne 0 ]; then
  echo "pip index versions $package failed (exit $rc) -- cannot tell whether a version starting" >&2
  echo "with $prefix is published; refusing to report \"false\" for what may just be an outage:" >&2
  echo "$versions_output" >&2
  exit 1
fi

if echo "$versions_output" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | grep -qE "^$(printf '%s' "$prefix" | sed 's/[.[\*^$]/\\&/g')"; then
  echo "true"
else
  echo "false"
fi
