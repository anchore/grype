#!/bin/sh
set -eu

TEST_INSTALL_SH=true
. "${INSTALL_SCRIPT_UNDER_TEST:-../../install.sh}"

get_release_tag() {
  printf '%s\n' "$3"
}

prep_signature_verification() {
  return 0
}

http_copy() {
  cat <<'SCRIPT'
printf '%s\n' "$@" > "$INSTALL_ARG_CAPTURE"
SCRIPT
}

test_dir=$(mktemp -d)
trap 'rm -rf "$test_dir"' EXIT
INSTALL_ARG_CAPTURE="$test_dir/actual"
export INSTALL_ARG_CAPTURE
install_path="$test_dir/bin with spaces"

# The old installer stores arguments in a scalar; supply the same value when
# testing a sourced historical script.
PROGRAM_ARGS="-b $install_path -d v0.80.0"

main -b "$install_path" -d v0.80.0
printf '%s\n' -b "$install_path" -d v0.80.0 > "$test_dir/expected"
diff -u "$test_dir/expected" "$INSTALL_ARG_CAPTURE"
