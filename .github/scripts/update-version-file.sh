#!/usr/bin/env bash
set -ue

BIN="grype"
DISTDIR=$1
VERSION=$2

# TODO: after v0.1.0 release, add the pre-release check back in. Currently we are only cutting beta releases so we want
# to let user's know when there is a new beta available, however, after v0.1.0 we will rarely be cutting beta releases.
# At that point we do not want to update the version file for new betas.
# if [[ $VERSION == *-* ]] ; then
#    echo "skipping publishing a version file (this is a pre-release: ${VERSION})"
#    exit 0
# fi

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