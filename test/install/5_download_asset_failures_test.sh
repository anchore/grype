. test_harness.sh

# serve release assets from a local fixture dir instead of the network (a missing file is a failed download)
http_download() {
  src="${FIXTURE_DIR}/${2##*/}"
  [ -f "${src}" ] || return 1
  cp "${src}" "$1"
}

# ensure every missing or mismatched piece of a release stops download_asset before anything is installed
test_download_asset_failures() {
  # download_asset [release-url-prefix] [download-path] [name] [os] [arch] [version] [format]

  # we are expecting error messages, which is confusing to look at in passing tests... disable logging for now
  log_set_priority -1

  OG_COSIGN_BINARY=${COSIGN_BINARY}

  tmpdir=$(mktemp -d)
  FIXTURE_DIR="${tmpdir}/release"
  dest="${tmpdir}/dest"
  args_file="${tmpdir}/cosign-args"
  mkdir -p "${FIXTURE_DIR}" "${dest}"

  # stub cosign that records it was called and always verifies
  COSIGN_BINARY="${tmpdir}/cosign"
  printf '#!/bin/sh\necho "$@" > "%s"\n' "${args_file}" > "${COSIGN_BINARY}"
  chmod +x "${COSIGN_BINARY}"

  asset="grype_0.120.0_linux_amd64.tar.gz"
  echo "the real asset" > "${FIXTURE_DIR}/${asset}"
  echo "$(hash_sha256 "${FIXTURE_DIR}/${asset}")  ${asset}" > "${FIXTURE_DIR}/grype_0.120.0_checksums.txt"
  echo "{}" > "${FIXTURE_DIR}/grype_0.120.0_checksums.txt.sigstore.json"

  run() {
    rm -rf "${dest:?}"/* "${args_file}"
    download_asset "https://example.invalid/v0.120.0" "${dest}" "grype" "linux" "amd64" "0.120.0" "tar.gz"
  }

  # happy path, verified and unverified
  VERIFY_SIGN=false
  asset_path=$(run)
  assertEquals "0" "$?" "complete release should download"
  assertEquals "${dest}/${asset}" "${asset_path}" "unexpected asset path"

  VERIFY_SIGN=true
  run >/dev/null
  assertEquals "0" "$?" "complete release should verify"
  assertContains "$(cat "${args_file}")" "--bundle ${dest}/grype_0.120.0_checksums.txt.sigstore.json" "bundle should be passed to cosign"

  # missing bundle: fail before cosign is ever called
  mv "${FIXTURE_DIR}/grype_0.120.0_checksums.txt.sigstore.json" "${tmpdir}/bundle"
  run >/dev/null
  assertEquals "1" "$?" "missing bundle should fail"
  assertFilesDoesNotExist "${args_file}" "cosign should not be called without a bundle"
  mv "${tmpdir}/bundle" "${FIXTURE_DIR}/grype_0.120.0_checksums.txt.sigstore.json"

  for VERIFY_SIGN in true false; do
    # asset does not match the checksums file
    echo "a tampered asset" > "${FIXTURE_DIR}/${asset}"
    run >/dev/null
    assertEquals "1" "$?" "checksum mismatch should fail (verify=${VERIFY_SIGN})"
    echo "the real asset" > "${FIXTURE_DIR}/${asset}"

    # missing asset
    mv "${FIXTURE_DIR}/${asset}" "${tmpdir}/asset"
    run >/dev/null
    assertEquals "1" "$?" "missing asset should fail (verify=${VERIFY_SIGN})"
    mv "${tmpdir}/asset" "${FIXTURE_DIR}/${asset}"

    # missing checksums file
    mv "${FIXTURE_DIR}/grype_0.120.0_checksums.txt" "${tmpdir}/checksums"
    run >/dev/null
    assertEquals "1" "$?" "missing checksums should fail (verify=${VERIFY_SIGN})"
    mv "${tmpdir}/checksums" "${FIXTURE_DIR}/grype_0.120.0_checksums.txt"
  done

  COSIGN_BINARY=${OG_COSIGN_BINARY}
  rm -rf -- "${tmpdir}"

  log_set_priority 0
}

run_test_case test_download_asset_failures
