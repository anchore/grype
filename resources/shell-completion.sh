#!/usr/bin/env bash

# Source this file in your shell sessions in order to use this shell completion.

complete -W "$(docker images --format '{{.Repository}}:{{.Tag}}')" grype
