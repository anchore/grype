#!/usr/bin/env bash
set -eu

IS_SNAPSHOT="$1"                        # e.g. "true", "false"

if [[ "${IS_SNAPSHOT}" == "true" ]]; then
  # This is a snapshot build —— skipping signing and notarization...
  exit 0
fi

GON_CONFIG="$2"                                       # e.g. "gon.hcl"
NEW_NAME_WITHOUT_EXTENSION="$3"                       # e.g. "./dist/syft-0.1.0"
ORIGINAL_NAME_WITHOUT_EXTENSION="./dist/output"       # This should match dmg and zip output_path in the gon config file, without the extension.

gon "${GON_CONFIG}"

# Rename outputs with specified desired name
mv -v "${ORIGINAL_NAME_WITHOUT_EXTENSION}.dmg" "${NEW_NAME_WITHOUT_EXTENSION}.dmg"
mv -v "${ORIGINAL_NAME_WITHOUT_EXTENSION}.zip" "${NEW_NAME_WITHOUT_EXTENSION}.zip"
