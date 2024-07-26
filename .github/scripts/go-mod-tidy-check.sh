#!/usr/bin/env bash
set -eu

ORIGINAL_STATE_DIR=$(mktemp -d "TEMP-original-state-XXXXXXXXX")
TIDY_STATE_DIR=$(mktemp -d "TEMP-tidy-state-XXXXXXXXX")

trap "cp -p ${ORIGINAL_STATE_DIR}/* ./ && git update-index -q --refresh && rm -fR ${ORIGINAL_STATE_DIR} ${TIDY_STATE_DIR}" EXIT

# capturing original state of files...
cp go.mod go.sum "${ORIGINAL_STATE_DIR}"

# capturing state of go.mod and go.sum after running go mod tidy...
go mod tidy
cp go.mod go.sum "${TIDY_STATE_DIR}"

set +e

# detect difference between the git HEAD state and the go mod tidy state
DIFF_MOD=$(diff -u "${ORIGINAL_STATE_DIR}/go.mod" "${TIDY_STATE_DIR}/go.mod")
DIFF_SUM=$(diff -u "${ORIGINAL_STATE_DIR}/go.sum" "${TIDY_STATE_DIR}/go.sum")

if [[ -n "${DIFF_MOD}" || -n "${DIFF_SUM}" ]]; then
    echo "go.mod diff:"
    echo "${DIFF_MOD}"
    echo "go.sum diff:"
    echo "${DIFF_SUM}"
    echo ""
    printf "FAILED! go.mod and/or go.sum are NOT tidy; please run 'go mod tidy'.\n\n"
    exit 1
fi
