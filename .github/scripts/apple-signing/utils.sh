SIGNING_IDENTITY_FILENAME=signing-identity.txt

## terminal goodies
PURPLE='\033[0;35m'
GREEN='\033[0;32m'
RED='\033[0;31m'
BOLD=$(tput -T linux bold)
RESET='\033[0m'

function success() {
  echo -e "\n${GREEN}${BOLD}$@${RESET}"
}

function title() {
  success "Task: $@"
}

function commentary() {
  echo -e "\n${PURPLE}# $@${RESET}"
}

function error() {
  echo -e "${RED}${BOLD}error: $@${RESET}"
}

function exit_with_error() {
  error $@
  exit 1
}

function exit_with_message() {
  success $@
  exit 0
}

function realpath {
  echo "$(cd $(dirname $1); pwd)/$(basename $1)";
}


# this function adds all of the existing keychains plus the new one which is the same as going to Keychain Access
# and selecting "Add Keychain" to make the keychain visible under "Custom Keychains". This is done with
# "security list-keychains -s" for some reason. The downside is that this sets the search path, not appends
# to it, so you will loose existing keychains in the search path... which is truly terrible.
function add_keychain() {
  keychains=$(security list-keychains -d user)
  keychainNames=();
  for keychain in $keychains
  do
    basename=$(basename "$keychain")
    keychainName=${basename::${#basename}-4}
    keychainNames+=("$keychainName")
  done

  echo "existing user keychains: ${keychainNames[@]}"

  security -v list-keychains -s "${keychainNames[@]}" "$1"
}

function exit_not_ci() {
    printf "WARNING! It looks like this isn't the CI environment. This script modifies the macOS Keychain setup in ways you probably wouldn't want for your own machine. It also requires an Apple Developer ID Certificate that you shouldn't have outside of the CI environment.\n\nExiting early to make sure nothing bad happens.\n"
    exit 1
}

CI_HOME="/Users/runner"

function assert_in_ci() {

  if [[ "${HOME}" != "${CI_HOME}" ]]; then
    exit_not_ci
  fi

  set +u
  if [ -z "${GITHUB_ACTIONS}" ]; then
    exit_not_ci
  fi
  set -u
}