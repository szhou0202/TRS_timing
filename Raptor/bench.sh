#!/usr/bin/env bash
set -euo pipefail

# Path to your header with the macro
PARAM_H="param.h"

# How to build & run tests
BUILD_CMD="make"
TEST_CMD="./raptor_test"
# or e.g. TEST_CMD="./run_tests"

# NOU values to test; override via CLI args if you want
if [ "$#" -gt 0 ]; then
  NOU_VALUES=("$@")
else
  NOU_VALUES=(8 16 32 64 128 256 512 1024)
fi

if [ ! -f "$PARAM_H" ]; then
  echo "Error: $PARAM_H not found" >&2
  exit 1
fi

# Backup original header
ORIG_BACKUP="$(mktemp param.h.orig.XXXXXX)"
cp "$PARAM_H" "$ORIG_BACKUP"

echo "Backed up original $PARAM_H to $ORIG_BACKUP"

# Function to patch NOU line
set_nou() {
  local value="$1"

  # GNU sed version (Linux). For macOS sed, see comment below.
#   sed -i.bak -E "s/^(#define[[:space:]]+NOU[[:space:]]+).*/\1${value}/" "$PARAM_H"

  # For macOS BSD sed instead use:
  sed -i '' -E "s/^(#define[[:space:]]+NOU[[:space:]]+).*/\1${value}/" $PARAM_H
}

for nou in "${NOU_VALUES[@]}"; do
  echo "========================================"
  echo "⇒ Setting NOU = $nou"
  set_nou "$nou"

  echo "⇒ Building..."
  eval "$BUILD_CMD"

  echo "⇒ Running tests (NOU = $nou)..."
  if ! eval "$TEST_CMD"; then
    echo "Tests failed for NOU = $nou" >&2
  fi
done

echo "========================================"
echo "Restoring original $PARAM_H"
cp "$ORIG_BACKUP" "$PARAM_H"

echo "Done."

