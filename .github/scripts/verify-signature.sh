#!/usr/bin/env bash
set -ue

DISTDIR=$1

export FINGERPRINT=$(gpg --verify ${DISTDIR}/*checksums.txt.sig ${DISTDIR}/*checksums.txt 2>&1 | grep 'using RSA key' | awk '{ print $NF }')

if [[ "${FINGERPRINT}" == "${SIGNING_FINGERPRINT}" ]]; then
    echo 'verified signature'
else
    echo "signed with unknown fingerprint: ${FINGERPRINT}"
    echo "           expected fingerprint: ${SIGNING_FINGERPRINT}"
    exit 1
fi
