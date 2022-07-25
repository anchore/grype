#!/usr/bin/env bash
set -eu

assert_in_ci

IDENTITY="Developer ID Application: ANCHORE, INC. (9MJHKYX5AT)"

set +xu
if [ -z "$APPLE_DEVELOPER_ID_CERT" ]; then
  exit_with_error "APPLE_DEVELOPER_ID_CERT not set"
fi

if [ -z "$APPLE_DEVELOPER_ID_CERT_PASS" ]; then
  exit_with_error "APPLE_DEVELOPER_ID_CERT_PASS not set"
fi

if [ -z "$DOCKER_USERNAME" ]; then
  exit_with_error "DOCKER_USERNAME not set"
fi

if [ -z "$DOCKER_PASSWORD" ]; then
  exit_with_error "DOCKER_PASSWORD not set"
fi

if [ -z "$GHCR_USERNAME" ]; then
  exit_with_error "GHCR_USERNAME not set"
fi

if [ -z "$GHCR_PASSWORD" ]; then
  exit_with_error "GHCR_PASSWORD not set"
fi
set -u

# setup_signing
#
# preps the MAC_SIGNING_IDENTITY env var for use in the signing process, using production certificate material
#
setup_signing() {
  title "setting up production certificate material"

  # Write signing certificate to disk from environment variable.
  p12_file="$HOME/developer_id_certificate.p12"
  echo -n "$APPLE_DEVELOPER_ID_CERT" | base64 --decode > "$p12_file"

  import_signing_certificate "$p12_file" "$APPLE_DEVELOPER_ID_CERT_PASS" "$IDENTITY"

  # Make this new keychain the user's default keychain, so that codesign will be able to find this certificate when we specify it during signing.
  security default-keychain -d "user" -s "${KEYCHAIN_PATH}"

  commentary "log into docker -- required for publishing (since the default keychain has now been replaced)"
  echo "${DOCKER_PASSWORD}" | docker login docker.io -u "${DOCKER_USERNAME}"  --password-stdin
  echo "${GHCR_PASSWORD}" | docker login ghcr.io -u "${GHCR_USERNAME}"  --password-stdin
}
