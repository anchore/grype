# disable using the install.sh entrypoint such that we can unit test
# script functions without invoking main()
TEST_INSTALL_SH=true

. ../../install.sh
set -u

assertTrue() {
  if eval "$1"; then
    echo "assertTrue failed: $2"
    exit 2
  fi
}

assertFalse() {
  if eval "$1"; then
    echo "assertFalse failed: $2"
    exit 2
  fi
}

assertEquals() {
  want=$1
  got=$2
  msg=$3
  if [ "$want" != "$got" ]; then
    echo "assertEquals failed: want='$want' got='$got' $msg"
    exit 2
  fi
}

assertFilesDoesNotExist() {
  path="$1"
  msg=$2
  if [ -f "${path}" ]; then
    echo "assertFilesDoesNotExist failed: path exists '$path': $msg"
    exit 2
  fi
}

assertFileExists() {
  path="$1"
  msg=$2
  if [ ! -f "${path}" ]; then
    echo "assertFileExists failed: path does not exist '$path': $msg"
    exit 2
  fi
}

assertFilesEqual() {
  want=$1
  got=$2
  msg=$3

  diff "$1" "$2"
  if [ $? -ne 0 ]; then
    echo "assertFilesEqual failed: $msg"
    exit 2
  fi
}

assertNotEquals() {
  want=$1
  got=$2
  msg=$3
  if [ "$want" = "$got" ]; then
    echo "assertNotEquals failed: want='$want' got='$got' $msg"
    exit 2
  fi
}

log_test_case() {
  echo "  running $@"
}

run_test_case_with_snapshot_release() {
  log_test_case ${@:1}

  worker_pid=$(setup_snapshot_server)
  trap "teardown_snapshot_server $worker_pid" EXIT

  # run test function with all arguments
  ${@:1}

  trap - EXIT
  teardown_snapshot_server "${worker_pid}"
}

serve_port=8000

setup_snapshot_server() {
  # if you want to see proof in the logs, feel free to adjust the redirection
  python3 -m http.server --directory "$(snapshot_dir)" $serve_port &> /dev/null &
  worker_pid=$!

  # it takes some time for the server to be ready...
  sleep 3

  echo "$worker_pid"
}

teardown_snapshot_server() {
  worker_pid="$1"

  kill $worker_pid
}

snapshot_version() {
  partial=$(ls ../../snapshot/*_checksums.txt | grep -o "_.*_checksums.txt")
  partial="${partial%_checksums.txt}"
  echo "${partial#_}"
}

snapshot_download_url() {
  echo "localhost:${serve_port}"
}

snapshot_dir() {
  echo "../../snapshot"
}

snapshot_checksums_path() {
  echo "$(ls $(snapshot_dir)/*_checksums.txt)"
}

snapshot_assets_count() {
  # example output before wc -l:

  #  ../../snapshot/grype_0.32.0-SNAPSHOT-e5e847a_linux_arm64.deb
  #  ../../snapshot/grype_0.32.0-SNAPSHOT-e5e847a_linux_arm64.tar.gz
  #  ../../snapshot/grype_0.32.0-SNAPSHOT-e5e847a_linux_amd64.rpm
  #  ../../snapshot/grype_0.32.0-SNAPSHOT-e5e847a_darwin_arm64.tar.gz
  #  ../../snapshot/grype_0.32.0-SNAPSHOT-e5e847a_linux_amd64.deb
  #  ../../snapshot/grype_0.32.0-SNAPSHOT-e5e847a_linux_arm64.rpm
  #  ../../snapshot/grype_0.32.0-SNAPSHOT-e5e847a_darwin_amd64.zip
  #  ../../snapshot/grype_0.32.0-SNAPSHOT-e5e847a_windows_amd64.zip
  #  ../../snapshot/grype_0.32.0-SNAPSHOT-e5e847a_darwin_arm64.zip
  #  ../../snapshot/grype_0.32.0-SNAPSHOT-e5e847a_linux_amd64.tar.gz
  #  ../../snapshot/grype_0.32.0-SNAPSHOT-e5e847a_darwin_amd64.tar.gz

  echo "$(find ../../snapshot -maxdepth 1 -type f | grep 'grype_' | grep -v checksums | wc -l | tr -d '[:space:]')"
}


snapshot_assets_archive_count() {
  # example output before wc -l:

  #  ../../snapshot/grype_0.32.0-SNAPSHOT-e5e847a_linux_arm64.tar.gz
  #  ../../snapshot/grype_0.32.0-SNAPSHOT-e5e847a_darwin_arm64.tar.gz
  #  ../../snapshot/grype_0.32.0-SNAPSHOT-e5e847a_darwin_amd64.zip
  #  ../../snapshot/grype_0.32.0-SNAPSHOT-e5e847a_windows_amd64.zip
  #  ../../snapshot/grype_0.32.0-SNAPSHOT-e5e847a_darwin_arm64.zip
  #  ../../snapshot/grype_0.32.0-SNAPSHOT-e5e847a_linux_amd64.tar.gz
  #  ../../snapshot/grype_0.32.0-SNAPSHOT-e5e847a_darwin_amd64.tar.gz

  echo "$(find ../../snapshot -maxdepth 1  -type f | grep 'grype_' | grep 'tar\|zip' | wc -l | tr -d '[:space:]')"
}


run_test_case() {
  log_test_case ${@:1}
  ${@:1}
}
