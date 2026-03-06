# change these if you want CI to not use previous stored cache
CLI_CACHE_BUSTER := "e5cdfd8"

.PHONY: cache.fingerprint
cache.fingerprint:
	find image-* -type f -exec md5sum {} + | awk '{print $1}' | sort | md5sum | tee cache.fingerprint && echo "$(CLI_CACHE_BUSTER)" >> cache.fingerprint
