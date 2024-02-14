#!/usr/bin/env bash
set -e

version=$(grep -E "github.com/anchore/syft" go.mod | awk '{print $NF}')

# ensure that the version is a release version (not a commit hash)
# a release in this case means that the go tooling resolved the version to a tag
# this does not guarantee that the tag has a github release associated with it
if [[ ! $version =~ ^v[0-9]+\.[0-9]+\.[0-9]?$ ]]; then
    echo "syft version in go.mod is not a release version: $version"
    echo "please update the version in go.mod to a release version and try again"
    exit 1
else
    echo "syft version in go.mod is a release version: $version"
fi
