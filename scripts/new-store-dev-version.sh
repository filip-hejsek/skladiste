#!/bin/bash
# Give the store format a new development version: a random string in
# src/store/dev-version, which skl compiles in. Run it once on a branch
# whose changes to the store format make stores of the version before
# unreadable. Stores of other development versions are never migrated.
#
# Usage: new-store-dev-version.sh
set -euo pipefail

file=$(dirname "$0")/../src/store/dev-version
version=dev-$(od -An -N6 -tx1 /dev/urandom | tr -d ' \n')
echo "$version" >"$file"
echo "$version"
