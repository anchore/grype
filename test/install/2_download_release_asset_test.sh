. test_harness.sh

test_download_release_asset() {
  release="$1"
  os="$2"
  arch="$3"
  format="$4"
  expected_mime_type="$5"

  # for troubleshooting
  # log_set_priority 10

  name=${PROJECT_NAME}
  version=$(tag_to_version ${release})
  github_download="https://github.com/${OWNER}/${REPO}/releases/download/${release}"

  tmpdir=$(mktemp -d)

  actual_filepath=$(download_asset "${github_download}" "${tmpdir}" "${name}" "${os}" "${arch}" "${version}" "${format}" )

  assertFileExists "${actual_filepath}" "download_asset os=${os} arch=${arch} format=${format}"

  actual_mime_type=$(file -b --mime-type ${actual_filepath})

  assertEquals "${expected_mime_type}" "${actual_mime_type}" "unexpected mimetype for os=${os} arch=${arch} format=${format}"

  rm -rf -- "$tmpdir"
}

# always test against the latest release
release=$(get_release_tag "${OWNER}" "${REPO}" "latest" )

# exercise all possible assets against a real github release (based on asset listing from https://github.com/anchore/grype/releases/tag/v0.32.0)

# verify all downloads against the checksums file + checksums file signature
VERIFY_SIGN=true

run_test_case test_download_release_asset "${release}" "darwin" "amd64" "tar.gz" "application/gzip"
run_test_case test_download_release_asset "${release}" "darwin" "arm64" "tar.gz" "application/gzip"
run_test_case test_download_release_asset "${release}" "linux" "amd64" "tar.gz" "application/gzip"
run_test_case test_download_release_asset "${release}" "linux" "amd64" "rpm" "application/x-rpm"
run_test_case test_download_release_asset "${release}" "linux" "amd64" "deb" "application/vnd.debian.binary-package"
run_test_case test_download_release_asset "${release}" "linux" "arm64" "tar.gz" "application/gzip"
run_test_case test_download_release_asset "${release}" "linux" "arm64" "rpm" "application/x-rpm"
run_test_case test_download_release_asset "${release}" "linux" "arm64" "deb" "application/vnd.debian.binary-package"
