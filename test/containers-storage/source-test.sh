#!/usr/bin/env bash
set -euo pipefail

builder="${1:?expected podman or buildah}"
case "$builder" in
  podman|buildah) ;;
  *)
    printf 'unsupported image builder: %s\n' "$builder" >&2
    exit 2
    ;;
esac

workspace_root="$(cd "$(dirname "$0")/../.." && pwd)"
grype_binary="${GRYPE_BINARY_LOCATION:-}"
if [[ -z "$grype_binary" ]]; then
  grype_binary="$(find "$workspace_root/snapshot" -type f -path '*/linux-build_linux_amd64*/grype' -print -quit)"
fi
if [[ -z "$grype_binary" ]]; then
  printf 'Linux snapshot binary not found under %s/snapshot\n' "$workspace_root" >&2
  exit 1
fi
chmod +x "$grype_binary"

test_dir="$(mktemp -d)"
cleanup() {
  if [[ "$(id -u)" -eq 0 ]]; then
    rm -rf "$test_dir"
  else
    "$builder" unshare rm -rf "$test_dir"
  fi
}
trap cleanup EXIT

export CONTAINERS_STORAGE_CONF="$test_dir/storage.conf"
cat > "$CONTAINERS_STORAGE_CONF" <<EOF
[storage]
driver = "vfs"
graphroot = "$test_dir/graphroot"
rootless_storage_path = "$test_dir/graphroot"
runroot = "$test_dir/runroot"
EOF

export GRYPE_CHECK_FOR_APP_UPDATE=false
export GRYPE_DB_CACHE_DIR="$test_dir/db"
"$grype_binary" db update
export GRYPE_DB_AUTO_UPDATE=false

image_ref="localhost/grype-containers-storage-test:latest"
case "$builder" in
  podman)
    podman build --pull=never --tag "$image_ref" "$workspace_root/test/containers-storage"
    ;;
  buildah)
    buildah bud --pull=false --tag "$image_ref" "$workspace_root/test/containers-storage"
    ;;
esac

for scan_mode in explicit automatic; do
  source_args=()
  if [[ "$scan_mode" == explicit ]]; then
    source_args=(--from containers-storage)
  fi
  printf 'Testing %s image resolution with %s\n' "$scan_mode" "$builder"
  "$grype_binary" "${source_args[@]}" "$image_ref" --output json > "$test_dir/$scan_mode.json"
  jq -e '
    .source.type == "image" and
    any(.matches[].artifact; .name == "lodash" and .version == "4.17.20" and .type == "npm")
  ' "$test_dir/$scan_mode.json" >/dev/null
done

printf 'Testing missing image with %s\n' "$builder"
if "$grype_binary" --from containers-storage localhost/grype-containers-storage-missing:latest --output json > "$test_dir/missing.json" 2> "$test_dir/missing.stderr"; then
  printf 'Expected the missing containers-storage image scan to fail\n' >&2
  exit 1
fi
grep -q 'containers-storage:' "$test_dir/missing.stderr"
if grep -q 'oci-registry:' "$test_dir/missing.stderr"; then
  printf 'Explicit containers-storage selection unexpectedly attempted registry resolution\n' >&2
  exit 1
fi
