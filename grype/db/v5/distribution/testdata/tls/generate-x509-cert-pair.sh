#!/usr/bin/env bash
set -eux

# we want to still use this on systems where there could be invalid characters in the hostname (e.g. ' or " characters)
HOSTNAME=$(hostname | sed "s/['']/'/g" | sed 's/[^a-zA-Z0-9.-]/-/g')

# create private key
openssl genrsa -out server.key 2048

# generate self-signed public key (cert) based on the private key
openssl req -new -x509 -sha256 \
    -key server.key \
    -out server.crt \
    -days 3650 \
    -reqexts SAN \
    -extensions SAN \
    -config <(cat /etc/ssl/openssl.cnf <(printf "[SAN]\nsubjectAltName=DNS:$HOSTNAME.local")) \
    -subj "/C=US/ST=Test/L=Test/O=Test/CN=$HOSTNAME.local"
