#!/usr/bin/env bash
set -u

if [ "$(git status --porcelain | wc -l)" -ne "0" ]; then
  echo "  🔴 there are uncommitted changes, please commit them before running this check"
  exit 1
fi

if ! make generate-db-schema; then
  echo "Generating database blob schemas failed"
  exit 1
fi

if [ "$(git status --porcelain | wc -l)" -ne "0" ]; then
  echo "  🔴 database blob schemas have uncommitted changes"
  echo "  Run 'task generate-db-schema' and commit the changes"
  echo ""
  git status --porcelain
  echo ""
  git diff schema/grype/db/
  exit 1
fi

echo "✅ Database blob schemas are up to date"
