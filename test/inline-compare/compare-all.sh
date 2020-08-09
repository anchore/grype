#!/usr/bin/env bash
set -eu

image_build_dir="./images"
builds=($(ls -d -1 images/*))
images=("debian:10.5" "centos:8.2.2004" "alpine:3.12.0")

# build images
for build_path in "${builds[@]}"; do
    echo "Building $build_path"
    pushd $build_path
        new_image=$(basename $build_path):latest
        docker build -q -t $new_image .

        images+=($new_image)
    popd
done

# gather all image analyses
for img in "${images[@]}"; do
    echo "Gathering facts for $img"
    COMPARE_IMAGE=${img} make gather-image
done

# compare all results
for img in "${images[@]}"; do
    echo "Comparing results for $img"
    COMPARE_IMAGE=${img} make compare-image
done