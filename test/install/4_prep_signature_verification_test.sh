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

# ensure the verification material is passed through to cosign and the old-cosign hint only shows when warranted
test_verify_sign() {
  # verify_sign [checksums-file-path] [verification-material-flags...]

  OG_COSIGN_BINARY=${COSIGN_BINARY}

  tmpdir=$(mktemp -d)
  args_file="${tmpdir}/args"
  hint="requires cosign v2.5.0 or newer"

  # stub cosign that records its arguments, then prints STUB_OUTPUT and exits with STUB_EXIT
  COSIGN_BINARY="${tmpdir}/cosign"
  cat > "${COSIGN_BINARY}" <<STUB
#!/bin/sh
echo "\$@" > "${args_file}"
echo "\${STUB_OUTPUT}"
exit "\${STUB_EXIT}"
STUB
  chmod +x "${COSIGN_BINARY}"

  identity="--certificate-identity https://github.com/${OWNER}/${REPO}/.github/workflows/release.yaml@refs/heads/main --certificate-oidc-issuer https://token.actions.githubusercontent.com"

  # bundle verification succeeds
  STUB_OUTPUT="Verified OK" STUB_EXIT=0 verify_sign "checksums.txt" --bundle "checksums.txt.sigstore.json" >/dev/null 2>&1
  assertEquals "0" "$?" "bundle verification should succeed"
  assertEquals "verify-blob checksums.txt --bundle checksums.txt.sigstore.json ${identity}" "$(cat "${args_file}")" "unexpected cosign args for bundle"

  # legacy verification succeeds
  STUB_OUTPUT="Verified OK" STUB_EXIT=0 verify_sign "checksums.txt" --certificate "c.pem" --signature "c.sig" >/dev/null 2>&1
  assertEquals "0" "$?" "legacy verification should succeed"
  assertEquals "verify-blob checksums.txt --certificate c.pem --signature c.sig ${identity}" "$(cat "${args_file}")" "unexpected cosign args for legacy"

  # cosign too old to read the bundle: fail with the hint (this is what cosign v2.2.4 through v2.4.1 print)
  output=$(STUB_OUTPUT="Error: bundle does not contain cert for verification, please provide public key" STUB_EXIT=1 verify_sign "checksums.txt" --bundle "b.json" 2>&1)
  assertEquals "1" "$?" "old cosign should fail verification"
  assertContains "${output}" "${hint}" "old cosign should get the version hint"

  # bad signature (e.g. tampered checksums): fail without the hint
  output=$(STUB_OUTPUT="Error: invalid signature when validating ASN.1 encoded signature" STUB_EXIT=1 verify_sign "checksums.txt" --bundle "b.json" 2>&1)
  assertEquals "1" "$?" "bad signature should fail verification"
  assertNotContains "${output}" "${hint}" "bad signature should not get the version hint"

  # unparseable bundle (e.g. a 404 body): fail without the hint
  output=$(STUB_OUTPUT="Error: invalid character 'N' looking for beginning of value" STUB_EXIT=1 verify_sign "checksums.txt" --bundle "b.json" 2>&1)
  assertEquals "1" "$?" "unparseable bundle should fail verification"
  assertNotContains "${output}" "${hint}" "unparseable bundle should not get the version hint"

  # legacy failure never gets the bundle hint, even with the same output
  output=$(STUB_OUTPUT="Error: bundle does not contain cert for verification, please provide public key" STUB_EXIT=1 verify_sign "checksums.txt" --certificate "c.pem" --signature "c.sig" 2>&1)
  assertEquals "1" "$?" "legacy failure should fail verification"
  assertNotContains "${output}" "${hint}" "legacy failure should not get the version hint"

  COSIGN_BINARY=${OG_COSIGN_BINARY}
  rm -rf -- "${tmpdir}"
}

run_test_case test_verify_sign
