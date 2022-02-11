#!/usr/bin/env bash
set -eu

NAME=grype-dev
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
DIR=$SCRIPT_DIR/dev-pki
FILE_PREFIX=$DIR/$NAME
IDENTITY=${NAME}-id-415d8c69793

## OpenSSL material

KEY_PASSWORD="letthedevin"
P12_PASSWORD="popeofnope"

KEY_FILE=$FILE_PREFIX-key.pem
CSR_FILE=$FILE_PREFIX-csr.pem
CERT_FILE=$FILE_PREFIX-cert.pem
EXT_FILE=$FILE_PREFIX-ext.cnf
P12_FILE=$FILE_PREFIX.p12

EXT_SECTION=codesign_reqext

## Keychain material

KEYCHAIN_NAME=$NAME
KEYCHAIN_PATH=$HOME/Library/Keychains/$KEYCHAIN_NAME-db
KEYCHAIN_PASSWORD="topsykretts"

# setup_signing
#
# preps the MAC_SIGNING_IDENTITY env var for use in the signing process, using ephemeral developer certificate material
#
function setup_signing() {
  # check to see if this has already been done... if so, bail!
  set +ue
  if security find-identity -p codesigning "$KEYCHAIN_PATH" | grep $IDENTITY ; then
      export MAC_SIGNING_IDENTITY=$IDENTITY
      commentary "skipping creating dev certificate material (already exists)"
      commentary "setting MAC_SIGNING_IDENTITY=${IDENTITY}"
      return 0
  fi
  set -ue

  title "setting up developer certificate material"

  mkdir -p "${DIR}"

  # configure the openssl extensions
  cat << EOF > $EXT_FILE
  [ req ]
  default_bits          = 2048                  # RSA key size
  encrypt_key           = yes                   # Protect private key
  default_md            = sha256                # MD to use
  utf8                  = yes                   # Input is UTF-8
  string_mask           = utf8only              # Emit UTF-8 strings
  prompt                = yes                   # Prompt for DN
  distinguished_name    = codesign_dn           # DN template
  req_extensions        = $EXT_SECTION          # Desired extensions

  [ codesign_dn ]
  commonName            = $IDENTITY
  commonName_max        = 64

  [ $EXT_SECTION ]
  keyUsage              = critical,digitalSignature
  extendedKeyUsage      = critical,codeSigning
  subjectKeyIdentifier  = hash
EOF

  title "create the private key"
  openssl genrsa \
            -des3 \
            -out "$KEY_FILE" \
            -passout "pass:$KEY_PASSWORD" \
           2048

  title "create the csr"
  openssl req \
            -new \
            -key "$KEY_FILE" \
            -out "$CSR_FILE" \
            -passin "pass:$KEY_PASSWORD" \
            -config "$EXT_FILE" \
            -subj "/CN=$IDENTITY"

  commentary "verify the csr: we should see X509 v3 extensions for codesigning in the CSR"
  openssl req -in "$CSR_FILE" -noout -text | grep -A1 "X509v3" || exit_with_error "could not find x509 extensions in CSR"

  title "create the certificate"
  # note: Extensions in certificates are not transferred to certificate requests and vice versa. This means that
  # just because the CSR has x509 v3 extensions doesn't mean that you'll see these extensions in the cert output.
  # To prove this do:
  # 	openssl x509 -text -noout -in server.crt | grep -A10 "X509v3 extensions:"
  # ... and you will see no output (if -extensions is not used). (see https://www.openssl.org/docs/man1.1.0/man1/x509.html#BUGS)
  # To get the extensions, use "-extensions codesign_reqext" when creating the cert. The codesign_reqext value matches
  # the section name in the ext file used in CSR / cert creation (-extfile and -config).
  openssl x509 \
            -req \
            -days 10000 \
            -in "$CSR_FILE" \
            -signkey "$KEY_FILE" \
            -out "$CERT_FILE" \
            -extfile "$EXT_FILE" \
            -passin "pass:$KEY_PASSWORD" \
            -extensions $EXT_SECTION

  commentary "verify the certificate: we should see our extensions"
  openssl x509 -text -noout -in $CERT_FILE | grep -A1 'X509v3' || exit_with_error "could not find x509 extensions in certificate"

  title "export cert and private key to .p12 file"
  # note: this step may be entirely optional, however, I found it useful to follow the prod path which goes the route of using a p12
  openssl pkcs12 \
            -export \
            -out "$P12_FILE" \
            -inkey "$KEY_FILE" \
            -in "$CERT_FILE" \
            -passin "pass:$KEY_PASSWORD" \
            -passout "pass:$P12_PASSWORD"


  title "create the dev keychain"

  # delete the keychain if it already exists
  if [ -f "$(KEYCHAIN_PATH)" ]; then
    security delete-keychain "$KEYCHAIN_NAME" &> /dev/null
  fi

  security create-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN_NAME"

  set +e
  if ! security verify-cert -k "$KEYCHAIN_PATH" -c "$CERT_FILE" &> /dev/null; then
    set -e
    title "import the cert into the dev keychain if it is not already trusted by the system"

    security import "$P12_FILE" -P $P12_PASSWORD -f pkcs12 -k "$KEYCHAIN_PATH" -T /usr/bin/codesign

    # note: set the partition list for this certificate's private key to include "apple-tool:" and "apple:" allows the codesign command to access this keychain item without an interactive user prompt.
    security set-key-partition-list -S "apple-tool:,apple:,codesign:" -s -k "$KEYCHAIN_PASSWORD" "$KEYCHAIN_PATH"

    # note: add-trusted-cert requires user interaction
    commentary "adding the developer certificate as a trusted certificate... (requires user interaction)"
    security add-trusted-cert -d -r trustRoot -k "$KEYCHAIN_PATH" "$CERT_FILE"
  else
    set -e
    commentary "...dev cert has already been imported onto the dev keychain"
  fi

  # remove any generated cert material since the keychain now has all of this material loaded
  rm -rf "${DIR}"

  commentary "make certain there are identities that can be used for code signing"
  security find-identity -p codesigning "$KEYCHAIN_PATH" | grep -C 30 "$IDENTITY" || exit_with_error "could not find identity that can be used with codesign"

  title "add the dev keychain to the search path for codesign"
  add_keychain $KEYCHAIN_NAME

  commentary "verify the keychain actually shows up"
  security list-keychains | grep "$KEYCHAIN_NAME" || exit_with_error "could not find new keychain"

  export MAC_SIGNING_IDENTITY=$IDENTITY
  commentary "setting MAC_SIGNING_IDENTITY=${IDENTITY}"

}

function cleanup_signing() {
  title "delete the dev keychain and all certificate material"
  set -xue
  security delete-keychain "$KEYCHAIN_NAME"
  rm -f "$KEYCHAIN_PATH"
  rm -rf "${DIR}"
}
