#!/usr/bin/env bash
set -eu

IS_SNAPSHOT="$1"                        # e.g. "true", "false"

if [[ "${IS_SNAPSHOT}" == "true" ]]; then
  # This is a snapshot build —— skipping signing and notarization...
  exit 0
fi

GON_CONFIG="$2"                         # e.g. "gon.hcl"
NEW_DMG_NAME="$3"                       # e.g. "./dist/syft-0.1.0.dmg"
ORIGINAL_DMG_NAME="./dist/output.dmg"   # This should match dmg output_path in the gon config file.

gon "${GON_CONFIG}"
mv -v "${ORIGINAL_DMG_NAME}" "${NEW_DMG_NAME}"
