. test_harness.sh

# search for an asset in a release checksums file
test_search_for_asset_release() {
  fixture=./test-fixtures/griffon_0.32.0_checksums.txt

  # search_for_asset [checksums-file-path] [name] [os] [arch] [format]

  # positive case
  actual=$(search_for_asset "${fixture}" "griffon" "linux" "amd64" "tar.gz")
  assertEquals "griffon_0.32.0_linux_amd64.tar.gz" "${actual}" "unable to find release asset"

  # negative cases
  actual=$(search_for_asset "${fixture}" "griffon" "Linux" "amd64" "tar.gz")
  assertEquals "" "${actual}" "found a release asset but did not expect to (os)"

  actual=$(search_for_asset "${fixture}" "griffon" "darwin" "amd64" "rpm")
  assertEquals "" "${actual}" "found a release asset but did not expect to (format)"

}

run_test_case test_search_for_asset_release


# search for an asset in a snapshot checksums file
test_search_for_asset_snapshot() {
  fixture=./test-fixtures/griffon_0.32.0-SNAPSHOT-d461f63_checksums.txt

  # search_for_asset [checksums-file-path] [name] [os] [arch] [format]

  # positive case
  actual=$(search_for_asset "${fixture}" "griffon" "linux" "amd64" "rpm")
  assertEquals "griffon_0.32.0-SNAPSHOT-d461f63_linux_amd64.rpm" "${actual}" "unable to find snapshot asset"

  # negative case
  actual=$(search_for_asset "${fixture}" "griffon" "linux" "amd64" "zip")
  assertEquals "" "${actual}" "found a snapshot asset but did not expect to (format)"
}

run_test_case test_search_for_asset_snapshot
