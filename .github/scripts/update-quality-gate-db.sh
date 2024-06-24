#!/bin/bash

# Run your command and capture the output
output=$(go run ../../cmd/grype/main.go db list)

# Extract the first instance of URL using grep, cut, and sed to trim leading whitespace
url=$(echo "$output" | grep -m 1 -o 'URL: .*' | cut -d' ' -f2- | sed 's/^[[:space:]]*//')

# Escape special characters in the URL for sed substitution
escaped_url=$(printf '%s\n' "$url" | sed -e 's/[\/&]/\\&/g')

# Replace TEST_DB_URL in specific Makefile using sed
sed -i '' -e "s|^TEST_DB_URL = .*|TEST_DB_URL = $escaped_url|" ../../test/quality/Makefile
