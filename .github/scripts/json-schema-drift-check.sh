#!/usr/bin/env bash
set -u

if [ "$(git status --porcelain | wc -l)" -ne "0" ]; then
  echo "  🔴 there are uncommitted changes, please commit them before running this check"
  exit 1
fi

if ! make generate-json-schema; then
  echo "Generating json schema failed"
  exit 1
fi

if [ "$(git status --porcelain | wc -l)" -ne "0" ]; then
  echo "  🔴 there are uncommitted changes, please commit them before running this check"
  exit 1
fi
