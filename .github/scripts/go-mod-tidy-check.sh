#!/usr/bin/env bash
set -eu

BACKUPS_DIR=$(mktemp -d "TEMP-backups-XXXXXXXXX")
GIT_HEAD_STATE_DIR=$(mktemp -d "TEMP-git-head-state-XXXXXXXXX")
TIDY_STATE_DIR=$(mktemp -d "TEMP-tidy-state-XXXXXXXXX")

trap "cp -v ${BACKUPS_DIR}/* ./ && rm -fR ${BACKUPS_DIR} ${GIT_HEAD_STATE_DIR} ${TIDY_STATE_DIR}" EXIT

echo "Backing up files from working tree..."
cp -v go.mod go.sum "${BACKUPS_DIR}"

echo "Capturing state of go.mod and go.sum from git HEAD..."
git checkout go.mod go.sum
cp -v go.mod go.sum "${GIT_HEAD_STATE_DIR}"
echo ""

echo "Capturing state of go.mod and go.sum after running go mod tidy..."
go mod tidy
cp -v go.mod go.sum "${TIDY_STATE_DIR}"
echo ""

set +e

# Detect difference between the git HEAD state and the go mod tidy state
DIFF_MOD=$(diff -u "${GIT_HEAD_STATE_DIR}/go.mod" "${TIDY_STATE_DIR}/go.mod")
DIFF_SUM=$(diff -u "${GIT_HEAD_STATE_DIR}/go.sum" "${TIDY_STATE_DIR}/go.sum")

if [[ -n "${DIFF_MOD}" || -n "${DIFF_SUM}" ]]; then
    echo "go.mod diff:"
    echo "${DIFF_MOD}"
    echo "go.sum diff:"
    echo "${DIFF_SUM}"
    echo ""
    printf "FAILED! go.mod and/or go.sum are NOT tidy on current git head; please run 'go mod tidy' and commit the change.\n\n"
    exit 1
fi
