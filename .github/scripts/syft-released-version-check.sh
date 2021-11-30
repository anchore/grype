#!/usr/bin/env sh

SYFT_LINE=$(cat go.mod | grep github.com/anchore/syft)

if [ "$(echo $SYFT_LINE | grep  -o '-' | wc -l)" -gt "1" ]; then
   echo "syft version is not a released version! $SYFT_LINE"
   exit 1
else
  echo 'syft version is a released version!'
fi