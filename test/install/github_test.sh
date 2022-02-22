. test_harness.sh

# check that we can extract single json values
test_extract_json_value() {
  fixture=./test-fixtures/github-api-grype-v0.32.0-release.json
  content=$(cat ${fixture})

  actual=$(extract_json_value "${content}" "tag_name")
  assertEquals "v0.32.0" "${actual}" "unable to find tag_name"

  actual=$(extract_json_value "${content}" "id")
  assertEquals "57501596" "${actual}" "unable to find tag_name"
}

run_test_case test_extract_json_value


# check that we can extract github release tag from github api json
test_github_release_tag() {
  fixture=./test-fixtures/github-api-grype-v0.32.0-release.json
  content=$(cat ${fixture})

  actual=$(github_release_tag "${content}")
  assertEquals "v0.32.0" "${actual}" "unable to find release tag"
}

run_test_case test_github_release_tag


# download a known good github release checksums and compare against a test-fixture
test_download_github_release_checksums() {
  tmpdir=$(mktemp -d)

  tag=v0.32.0
  github_download="https://github.com/anchore/grype/releases/download/${tag}"
  name=${PROJECT_NAME}
  version=$(tag_to_version "${tag}")

  actual_filepath=$(download_github_release_checksums "${github_download}" "${name}" "${version}" "${tmpdir}")
  assertFilesEqual \
    "./test-fixtures/grype_0.32.0_checksums.txt" \
    "${actual_filepath}" \
    "unable to find release tag"

  rm -rf -- "$tmpdir"
}

run_test_case test_download_github_release_checksums


# download a checksums file from a locally served-up snapshot directory and compare against the file in the snapshot dir
test_download_github_release_checksums_snapshot() {
  tmpdir=$(mktemp -d)

  github_download=$(snapshot_download_url)
  name=${PROJECT_NAME}
  version=$(snapshot_version)

  actual_filepath=$(download_github_release_checksums "${github_download}" "${name}" "${version}" "${tmpdir}")
  assertFilesEqual \
    "$(snapshot_checksums_path)" \
    "${actual_filepath}" \
    "unable to find release tag"

  rm -rf -- "$tmpdir"
}

run_test_case_with_snapshot_release test_download_github_release_checksums_snapshot