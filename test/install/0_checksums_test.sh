. test_harness.sh

# search for an asset in a release checksums file
test_search_for_asset_release() {
  fixture=./test-fixtures/grype_0.32.0_checksums.txt

  # search_for_asset [checksums-file-path] [name] [os] [arch] [format]

  # positive case
  actual=$(search_for_asset "${fixture}" "grype" "linux" "amd64" "tar.gz")
  assertEquals "grype_0.32.0_linux_amd64.tar.gz" "${actual}" "unable to find release asset"

  # negative cases
  actual=$(search_for_asset "${fixture}" "grype" "Linux" "amd64" "tar.gz")
  assertEquals "" "${actual}" "found a release asset but did not expect to (os)"

  actual=$(search_for_asset "${fixture}" "grype" "darwin" "amd64" "rpm")
  assertEquals "" "${actual}" "found a release asset but did not expect to (format)"

}

run_test_case test_search_for_asset_release


# search for an asset in a snapshot checksums file
test_search_for_asset_snapshot() {
  fixture=./test-fixtures/grype_0.32.0-SNAPSHOT-d461f63_checksums.txt

  # search_for_asset [checksums-file-path] [name] [os] [arch] [format]

  # positive case
  actual=$(search_for_asset "${fixture}" "grype" "linux" "amd64" "rpm")
  assertEquals "grype_0.32.0-SNAPSHOT-d461f63_linux_amd64.rpm" "${actual}" "unable to find snapshot asset"

  # negative case
  actual=$(search_for_asset "${fixture}" "grype" "linux" "amd64" "zip")
  assertEquals "" "${actual}" "found a snapshot asset but did not expect to (format)"
}

run_test_case test_search_for_asset_snapshot

# verify 256 digest of a file
test_hash_sha256() {
  target=./test-fixtures/assets/valid/grype_0.78.0_linux_arm64.tar.gz

  # hash_sha256 [target]

  # positive case
  actual=$(hash_sha256 "${target}")
  assertEquals "8d57abb57a0dae3ff23c8f0df1f51951b7772822e0d560e860d6f68c24ef6d3d" "${actual}" "mismatched checksum"
}

run_test_case test_hash_sha256

# verify 256 digest of a file relative to the checksums file
test_hash_sha256_verify() {

  # hash_sha256_verify [target] [checksums]


  # positive case

  checksums=./test-fixtures/assets/valid/checksums.txt
  target=./test-fixtures/assets/valid/grype_0.78.0_linux_arm64.tar.gz

  hash_sha256_verify "${target}" "${checksums}"
  assertEquals "0" "$?" "mismatched checksum"


  # negative case

  # we are expecting error messages, which is confusing to look at in passing tests... disable logging for now
  log_set_priority -1

  checksums=./test-fixtures/assets/invalid/checksums.txt
  target=./test-fixtures/assets/invalid/grype_0.78.0_linux_arm64.tar.gz

  hash_sha256_verify "${target}" "${checksums}"
  assertEquals "1" "$?" "verification did not catch mismatched checksum"

  # restore logging...
  log_set_priority 0
}

run_test_case test_hash_sha256_verify
