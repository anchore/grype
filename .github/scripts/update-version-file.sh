#!/usr/bin/env bash
set -ue

BIN="grype"
DISTDIR=$1
VERSION=$2

# the source of truth as to whether we want to notify users of an update is if the release just created is NOT
# flagged as a pre-release on github
if [[ "$(curl -SsL https://api.github.com/repos/anchore/${BIN}/releases/tags/${VERSION} | jq .prerelease)" == "true" ]] ; then
   echo "skipping publishing a version file (this is a pre-release: ${VERSION})"
   exit 0
fi

echo "creating and publishing version file"

# create a version file for version-update checks
echo "${VERSION}" | tee ${DISTDIR}/VERSION

# upload the version file that supports the application version update check
docker run --rm \
    -i \
    -e AWS_DEFAULT_REGION=us-west-2 \
    -e AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID} \
    -e AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY} \
    -v $(pwd)/${DISTDIR}/:/distmount \
    amazon/aws-cli \
        s3 cp /distmount/VERSION s3://toolbox-data.anchore.io/${BIN}/releases/latest/VERSION