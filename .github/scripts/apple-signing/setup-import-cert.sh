#!/usr/bin/env bash
set -eu

KEYCHAIN_NAME="syft-ephemeral-keychain"
KEYCHAIN_PATH="$HOME/Library/Keychains/${KEYCHAIN_NAME}-db"

# import_signing_certificate
#
# imports a cert from a p12 file into a keychain used for codesigning
#
function import_signing_certificate() {
  p12_file=$1
  p12_password=$2
  identity=$3

  keychain_password="$(openssl rand -base64 100)"

  title "create the a new keychain"

  security create-keychain -p "$keychain_password" "$KEYCHAIN_NAME"
  security set-keychain-settings -lut 21600 "$KEYCHAIN_PATH"
  security unlock-keychain -p "$keychain_password" "$KEYCHAIN_PATH"

  if [ ! -f "$KEYCHAIN_PATH" ]; then
    exit_with_error "cannot find keychain '$KEYCHAIN_PATH'"
  fi

  set +e
  if ! security verify-cert -k "$KEYCHAIN_PATH" -c "$p12_file" &> /dev/null; then
    set -e
    title "import the cert into the new keychain if it is not already trusted by the system"

    # '-t cert' is vital since it side-steps the need for user interaction with "security add-trusted-cert" (which has wider security implications)
    security import "$p12_file" -P "$p12_password" -t cert -f pkcs12 -k "$KEYCHAIN_PATH" -T /usr/bin/codesign

    # note: set the partition list for this certificate's private key to include "apple-tool:" and "apple:" allows the codesign command to access this keychain item without an interactive user prompt.
    security set-key-partition-list -S "apple-tool:,apple:,codesign:" -s -k "$keychain_password" "$KEYCHAIN_PATH"
  else
    set -e
    commentary "...cert has already been imported onto the new keychain"
  fi

  commentary "make certain there are identities that can be used for code signing"
  security find-identity -p codesigning "$KEYCHAIN_PATH" | grep -C 30 "$identity" || exit_with_error "could not find identity that can be used with codesign"

  title "add the new keychain to the search path for codesign"
  add_keychain "$KEYCHAIN_NAME"

  commentary "verify the new keychain can be found by the security sub-system"
  security list-keychains | grep "$KEYCHAIN_NAME" || exit_with_error "could not find new keychain"

  export MAC_SIGNING_IDENTITY=$identity
  commentary "setting MAC_SIGNING_IDENTITY=${identity}"

}
