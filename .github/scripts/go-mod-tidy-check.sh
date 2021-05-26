#!/usr/bin/env bash
set -u

TMP_GOMOD=$(mktemp)
TMP_GOSUM=$(mktemp)

trap "rm -f ${TMP_GOSUM} ${TMP_GOMOD}" EXIT

cp go.mod "${TMP_GOMOD}"
cp go.sum "${TMP_GOSUM}"

go mod tidy

DIFF_MOD=$(diff -u "${TMP_GOMOD}" go.mod)
DIFF_SUM=$(diff -u "${TMP_GOSUM}" go.sum)

cp "${TMP_GOMOD}" go.mod
cp "${TMP_GOSUM}" go.sum

if [[ -n "${DIFF_MOD}" || -n "${DIFF_SUM}" ]]; then
    echo "go.mod and/or go.sum are not tidy; please run go mod tidy"
    echo "go.mod diff:"
    echo "${DIFF_MOD}"
    echo "go.sum diff:"
    echo "${DIFF_SUM}"
    exit 1
fi
