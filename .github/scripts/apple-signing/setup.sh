#!/usr/bin/env bash
set -eu -o pipefail

IS_SNAPSHOT="$1"

## grab utilities
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
. "$SCRIPT_DIR"/utils.sh
mkdir -p "$SCRIPT_DIR/log"

main() {
  # defines KEYCHAIN_NAME and KEYCHAIN_PATH
  . "$SCRIPT_DIR"/setup-import-cert.sh

  case "$IS_SNAPSHOT" in

    "1" |  "true" | "yes")
      commentary "assuming development setup..."
      . "$SCRIPT_DIR"/setup-dev.sh
      ;;

    "0" |  "false" | "no")
      commentary "assuming production setup..."
      . "$SCRIPT_DIR"/setup-prod.sh
      ;;

    *)
      exit_with_error "could not determine if this was a production build (isSnapshot='$IS_SNAPSHOT')"
      ;;
  esac

  # load up all signing material into a keychain (note: this should set the MAC_SIGNING_IDENTITY env var)
  setup_signing

  # write out identity to a file
  echo -n "$MAC_SIGNING_IDENTITY" > "$SCRIPT_DIR/$SIGNING_IDENTITY_FILENAME"
}

# capture all output from a subshell to log output additionally to a file (as well as the terminal)
( (
  set +u
  if [ -n "$SKIP_SIGNING" ]; then
      commentary "skipping signing setup..."
  else
    set -u
    main
  fi
) 2>&1) | tee "$SCRIPT_DIR/log/setup.txt"