. test_harness.sh

test_compare_semver() {
  # compare_semver [version1] [version2]

  # positive cases (version1 >= version2)
  compare_semver "0.32.0" "0.32.0"
  assertEquals "0" "$?" "+ versions should equal"

  compare_semver "0.32.1" "0.32.0"
  assertEquals "0" "$?" "+ patch version should be greater"

  compare_semver "0.33.0" "0.32.0"
  assertEquals "0" "$?" "+ minor version should be greater"

  compare_semver "0.333.0" "0.32.0"
  assertEquals "0" "$?" "+ minor version should be greater (different length)"

  compare_semver "00.33.00" "0.032.0"
  assertEquals "0" "$?" "+ minor version should be greater (different length reversed)"

  compare_semver "1.0.0" "0.9.9"
  assertEquals "0" "$?" "+ major version should be greater"

  compare_semver "v1.0.0" "1.0.0"
  assertEquals "0" "$?" "+ can remove leading 'v' from version"

  # negative cases (version1 < version2)
  compare_semver "0.32.0" "0.32.1"
  assertEquals "1" "$?" "- patch version should be less"

  compare_semver "0.32.7" "0.33.0"
  assertEquals "1" "$?" "- minor version should be less"

  compare_semver "00.00032.070" "0.33.0"
  assertEquals "1" "$?" "- minor version should be less (different length)"

  compare_semver "0.32.7" "00.0033.000"
  assertEquals "1" "$?" "- minor version should be less (different length reversed)"

  compare_semver "1.9.9" "2.0.1"
  assertEquals "1" "$?" "- major version should be less"

  compare_semver "1.0.0" "v2.0.0"
  assertEquals "1" "$?" "- can remove leading 'v' from version"
}

run_test_case test_compare_semver

# ensure that various signature verification pre-requisites are correctly checked for
test_prep_signature_verification() {
  # prep_sign_verification [version]

  # we are expecting error messages, which is confusing to look at in passing tests... disable logging for now
  log_set_priority -1

  # backup original values...
  OG_COSIGN_BINARY=${COSIGN_BINARY}

  # check the verification path...
  VERIFY_SIGN=true

  # release does not support signature verification
  prep_signature_verification "0.71.0"
  assertEquals "1" "$?" "release does not support signature verification"

  # check that the COSIGN binary exists
  COSIGN_BINARY=fake-cosign-that-doesnt-exist
  prep_signature_verification "0.80.0"
  assertEquals "1" "$?" "cosign binary verification failed"
  # restore original values...
  COSIGN_BINARY=${OG_COSIGN_BINARY}

  # ignore any failing conditions since we are not verifying the signature
  VERIFY_SIGN=false
  prep_signature_verification "0.71.0"
  assertEquals "0" "$?" "release support verification should not have been triggered"

  COSIGN_BINARY=fake-cosign-that-doesnt-exist
  prep_signature_verification "0.80.0"
  assertEquals "0" "$?" "cosign binary verification should not have been triggered"
  # restore original values...
  COSIGN_BINARY=${OG_COSIGN_BINARY}

  # restore logging...
  log_set_priority 0
}

run_test_case test_prep_signature_verification
