# change these if you want CI to not use previous stored cache
INTEGRATION_CACHE_BUSTER := "894d8ca"

.PHONY: cache.fingerprint
cache.fingerprint:
	find image-* -type f -exec md5sum {} + | awk '{print $1}' | sort | tee /dev/stderr | md5sum | tee cache.fingerprint && echo "$(INTEGRATION_CACHE_BUSTER)" >> cache.fingerprint
