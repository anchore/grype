. test_harness.sh

# make certain main defers to the (stubbed) tagged release script regardless of the caller's env
DOWNLOAD_TAG_INSTALL_SCRIPT=true

get_release_tag() {
  printf '%s\n' "$3"
}

prep_signature_verification() {
  return 0
}

# the "tagged release script" records each argument it receives, one bracketed arg per line
http_copy() {
  cat <<'SCRIPT'
printf '[%s]\n' "$@" > "$INSTALL_ARG_CAPTURE"
SCRIPT
}

test_release_script_receives_original_args() {
  test_dir=$(mktemp -d)
  INSTALL_ARG_CAPTURE="${test_dir}/actual"
  export INSTALL_ARG_CAPTURE

  # note: paths are read here instead of passed to run_test_case, which word-splits its arguments
  while IFS= read -r install_path; do
    main -b "${install_path}" -d v0.80.0

    printf '[%s]\n' -b "${install_path}" -d v0.80.0 > "${test_dir}/expected"
    assertFilesEqual "${test_dir}/expected" "${INSTALL_ARG_CAPTURE}" "args forwarded to the release script should match the original args (path='${install_path}')"
  done <<'PATHS'
/tmp/bin with spaces
/tmp/bin*
/tmp/it's "quoted"
PATHS

  rm -rf -- "${test_dir}"
}

run_test_case test_release_script_receives_original_args
