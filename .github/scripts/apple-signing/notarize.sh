#!/usr/bin/env bash

set +xu
if [ -z "$AC_USERNAME" ]; then
  exit_with_error "AC_USERNAME not set"
fi

if [ -z "$AC_PASSWORD" ]; then
  exit_with_error "AC_PASSWORD not set"
fi
set -u


# notarize [archive-path]
#
notarize() {
  binary_path=$1
  archive_path=${binary_path}-archive-for-notarization.zip

  title "archiving release binary into ${archive_path}"

  parent=$(dirname "$binary_path")
  (
    cd "${parent}" && zip "${archive_path}" "$(basename ${binary_path})"
  )

  if [ ! -f "$archive_path" ]; then
    exit_with_error "cannot find payload for notarization: $archive_path"
  fi

  # install gon
  which gon || (go install github.com/mitchellh/gon/cmd/gon@c3afcf0180c2f21feca1a76eb4ffeef59c6197d6)

  # create config (note: json via stdin with gon is broken, can only use HCL from file)
  hcl_file=$(mktemp).hcl

  cat <<EOF > "$hcl_file"
notarize {
  path = "$archive_path"
  bundle_id = "com.anchore.toolbox.grype"
}

apple_id {
   username = "$AC_USERNAME"
   password = "@env:AC_PASSWORD"
}
EOF

  gon -log-level info "$hcl_file"

  rm "${hcl_file}" "${archive_path}"
}

