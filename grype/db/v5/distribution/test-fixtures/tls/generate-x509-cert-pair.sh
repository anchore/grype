#!/usr/bin/env bash
set -eux

# create private key
openssl genrsa -out server.key 2048

# generate self-signed public key (cert) based on the private key
openssl req -new -x509 -sha256 \
    -key server.key \
    -out server.crt \
    -days 3650 \
    -reqexts SAN \
    -extensions SAN \
    -config <(cat /etc/ssl/openssl.cnf <(printf "[SAN]\nsubjectAltName=DNS:$(hostname).local")) \
    -subj "/C=US/ST=Test/L=Test/O=Test/CN=$(hostname).local"

