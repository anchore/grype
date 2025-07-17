. test_harness.sh

INSTALL_ARCHIVE_POSITIVE_CASES=0

# helper for asserting install_asset positive cases
test_positive_snapshot_install_asset() {
  os="$1"
  arch="$2"
  format="$3"

  # for troubleshooting
  # log_set_priority 10

  name=${PROJECT_NAME}
  binary=$(get_binary_name "${os}" "${arch}" "${PROJECT_NAME}")
  github_download=$(snapshot_download_url)
  version=$(snapshot_version)

  download_dir=$(mktemp -d)
  install_dir=$(mktemp -d)

  download_and_install_asset "${github_download}" "${download_dir}" "${install_dir}" "${name}" "${os}" "${arch}" "${version}" "${format}" "${binary}"

  assertEquals "0" "$?" "download/install did not succeed"

  expected_path="${install_dir}/${binary}"
  assertFileExists "${expected_path}" "install_asset os=${os} arch=${arch} format=${format}"

  # directory structure for arch has been updated as of go 1.18
  # https://goreleaser.com/customization/build/#why-is-there-a-_v1-suffix-on-amd64-buildsjk
  if [ $arch == "amd64" ]; then
	  arch="amd64_v1"
  fi

  local_suffix=""
  if [ "${arch}" == "arm64" ]; then
    local_suffix="_v8.0"
  fi

  if [ "${arch}" == "ppc64le" ]; then
    local_suffix="_power8"
  fi


  assertFilesEqual \
    "$(snapshot_dir)/${os}-build_${os}_${arch}${local_suffix}/${binary}" \
    "${expected_path}" \
    "unable to verify installation of os=${os} arch=${arch} format=${format}"

 ((INSTALL_ARCHIVE_POSITIVE_CASES++))

  rm -rf -- "$download_dir"
  rm -rf -- "$install_dir"
}

# helper for asserting install_asset negative cases
test_negative_snapshot_install_asset() {
  os="$1"
  arch="$2"
  format="$3"

  # for troubleshooting
  # log_set_priority 10

  name=${PROJECT_NAME}
  binary=$(get_binary_name "${os}" "${arch}" "${PROJECT_NAME}")
  github_download=$(snapshot_download_url)
  version=$(snapshot_version)

  download_dir=$(mktemp -d)
  install_dir=$(mktemp -d)

  download_and_install_asset "${github_download}" "${download_dir}" "${install_dir}" "${name}" "${os}" "${arch}" "${version}" "${format}" "${binary}"

  assertNotEquals "0" "$?" "download/install should have failed but did not"

  rm -rf -- "$download_dir"
  rm -rf -- "$install_dir"
}


test_install_asset_exercised_all_archive_assets() {
  expected=$(snapshot_assets_archive_count)

  assertEquals "${expected}" "${INSTALL_ARCHIVE_POSITIVE_CASES}" "did not download all possible archive assets (missing an os/arch/format variant?)"
}


worker_pid=$(setup_snapshot_server)
trap 'teardown_snapshot_server ${worker_pid}' EXIT

# exercise all possible archive assets (not rpm/deb/dmg) against a snapshot build
run_test_case test_positive_snapshot_install_asset "linux" "amd64" "tar.gz"
run_test_case test_positive_snapshot_install_asset "linux" "arm64" "tar.gz"
run_test_case test_positive_snapshot_install_asset "linux" "s390x" "tar.gz"
run_test_case test_positive_snapshot_install_asset "linux" "ppc64le" "tar.gz"
run_test_case test_positive_snapshot_install_asset "darwin" "amd64" "tar.gz"
run_test_case test_positive_snapshot_install_asset "darwin" "arm64" "tar.gz"
run_test_case test_positive_snapshot_install_asset "windows" "amd64" "zip"

# let's make certain we covered all assets that were expected
run_test_case test_install_asset_exercised_all_archive_assets

# make certain we handle missing assets alright
run_test_case test_negative_snapshot_install_asset "bogus" "amd64" "zip"

trap - EXIT
teardown_snapshot_server "${worker_pid}"
