#!/usr/bin/env bash
set -eu

assert_in_ci

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
set -u

# setup_signing
#
# preps the MAC_SIGNING_IDENTITY env var for use in the signing process, using production certificate material
#
setup_signing() {
  title "setting up production certificate material"

  # Write signing certificate to disk from environment variable.
  cert_file="$HOME/developer_id_certificate.p12"
  echo -n "$APPLE_DEVELOPER_ID_CERT" | base64 --decode > "$cert_file"

  # In order to have all keychain interactions avoid an interactive user prompt, we need to control the password for the keychain in question, which means we need to create a new keychain into which we'll import the signing certificate and from which we'll later access this certificate during code signing.
  ephemeral_keychain="ci-ephemeral-keychain"
  ephemeral_keychain_password="$(openssl rand -base64 100)"
  security create-keychain -p "${ephemeral_keychain_password}" "${ephemeral_keychain}"

  # Import signing certificate into the keychain. (This is a pre-requisite for gon, which is invoked via goreleaser.)
  ephemeral_keychain_full_path="$HOME/Library/Keychains/${ephemeral_keychain}-db"
  security import "${cert_file}" -k "${ephemeral_keychain_full_path}" -P "${APPLE_DEVELOPER_ID_CERT_PASS}" -T "$(command -v codesign)"

  # Setting the partition list for this certificate's private key to include "apple-tool:" and "apple:" allows the codesign command to access this keychain item without an interactive user prompt. (codesign is invoked by gon.)
  security set-key-partition-list -S "apple-tool:,apple:" -s -k "${ephemeral_keychain_password}" "${ephemeral_keychain_full_path}"

  # Make this new keychain the user's default keychain, so that codesign will be able to find this certificate when we specify it during signing.
  security default-keychain -d "user" -s "${ephemeral_keychain_full_path}"

  # TODO: extract this from the certificate material itself
  export MAC_SIGNING_IDENTITY="Developer ID Application: ANCHORE, INC. (9MJHKYX5AT)"
  commentary "setting MAC_SIGNING_IDENTITY=${MAC_SIGNING_IDENTITY}"

  commentary "log into docker -- required for publishing (since the default keychain has now been replaced)"
  echo "${DOCKER_PASSWORD}" | docker login docker.io -u "${DOCKER_USERNAME}"  --password-stdin
}
