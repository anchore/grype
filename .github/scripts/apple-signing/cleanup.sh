#!/usr/bin/env bash
set -eu

# grab utilities
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
. "$SCRIPT_DIR"/utils.sh

# cleanup any dev certs left behind
. "$SCRIPT_DIR"/setup-import-cert.sh # defines KEYCHAIN_NAME and KEYCHAIN_PATH
. "$SCRIPT_DIR"/setup-dev.sh
cleanup_dev_signing
