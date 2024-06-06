NAME=grype

# for local testing (not testing within containers) use the binny-managed version of cosign.
# this also means that the user does not need to install cosign on their system to run tests.
COSIGN_BINARY=../../.tool/cosign

IMAGE_NAME=$(NAME)-install.sh-env
UBUNTU_IMAGE=$(IMAGE_NAME):ubuntu-20.04
ALPINE_IMAGE=$(IMAGE_NAME):alpine-3.6
BUSYBOX_IMAGE=$(IMAGE_NAME):busybox-1.36

ENVS=./environments
DOCKER_RUN=docker run --rm -t -w /project/test/install -v $(shell pwd)/../../:/project
UNIT=make unit-run

# acceptance testing is running the current install.sh against the latest release. Note: this could be a problem down
# the line if there are breaking changes made that don't align with the latest release (but will be OK with the next
# release). This tests both installing with signature verification and without.
ACCEPTANCE_CMD=sh -c '../../install.sh -v -b /usr/local/bin && grype version && rm /usr/local/bin/grype && ../../install.sh -b /usr/local/bin && grype version'
# we also want to test against a previous release to ensure that install.sh defers execution to a former install.sh
# this version should be at least as recent as when grype was publishing for darwin arm64 as that is what the github runner uses for osx validation
PREVIOUS_RELEASE=v0.60.0
ACCEPTANCE_PREVIOUS_RELEASE_CMD=sh -c "../../install.sh -b /usr/local/bin $(PREVIOUS_RELEASE) && grype version"

# CI cache busting values; change these if you want CI to not use previous stored cache
INSTALL_TEST_CACHE_BUSTER=894d8ca

define title
    @printf '\n≡≡≡[ $(1) ]≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡\n'
endef

.PHONY: test
test: unit acceptance

.PHONY: ci-test-mac
ci-test-mac: unit-run acceptance-local

# note: do not add acceptance-local to this list
.PHONY: acceptance
acceptance: acceptance-ubuntu-20.04 acceptance-alpine-3.6 acceptance-busybox-1.36

.PHONY: unit
unit: unit-ubuntu-20.04

.PHONY: unit-local
unit-local:
	$(call title,unit tests)
	@for f in $(shell ls *_test.sh); do echo "Running unit test suite '$${f}'"; bash -c "COSIGN_BINARY=$(COSIGN_BINARY) ./$${f}" || exit 1; done

.PHONY: unit-run
unit-run:
	$(call title,unit tests)
	@for f in $(shell ls *_test.sh); do echo "Running unit test suite '$${f}'"; bash $${f} || exit 1; done

.PHONY: acceptance-local
acceptance-local: acceptance-current-release-local acceptance-previous-release-local

.PHONY: acceptance-current-release-local
acceptance-current-release-local:
	$(ACCEPTANCE_CMD)

.PHONY: acceptance-previous-release-local
acceptance-previous-release-local:
	$(ACCEPTANCE_PREVIOUS_RELEASE_CMD)
	grype version | grep $(shell echo $(PREVIOUS_RELEASE)| tr -d "v")

.PHONY: save
save: ubuntu-20.04 alpine-3.6 busybox-1.36
	@mkdir cache || true
	docker image save -o cache/ubuntu-env.tar $(UBUNTU_IMAGE)
	docker image save -o cache/alpine-env.tar $(ALPINE_IMAGE)
	docker image save -o cache/busybox-env.tar $(BUSYBOX_IMAGE)

.PHONY: load
load:
	docker image load -i cache/ubuntu-env.tar
	docker image load -i cache/alpine-env.tar
	docker image load -i cache/busybox-env.tar

## UBUNTU #######################################################

.PHONY: acceptance-ubuntu-20.04
acceptance-ubuntu-20.04: ubuntu-20.04
	$(call title,ubuntu:20.04 - acceptance)
	$(DOCKER_RUN) $(UBUNTU_IMAGE) \
		$(ACCEPTANCE_CMD)

.PHONY: unit-ubuntu-20.04
unit-ubuntu-20.04: ubuntu-20.04
	$(call title,ubuntu:20.04 - unit)
	$(DOCKER_RUN) $(UBUNTU_IMAGE) \
		$(UNIT)

.PHONY: ubuntu-20.04
ubuntu-20.04:
	$(call title,ubuntu:20.04 - build environment)
	docker build -t $(UBUNTU_IMAGE) -f $(ENVS)/Dockerfile-ubuntu-20.04 .

## ALPINE #######################################################

# note: unit tests cannot be run with sh (alpine dosn't have bash by default)

.PHONY: acceptance-alpine-3.6
acceptance-alpine-3.6: alpine-3.6
	$(call title,alpine:3.6 - acceptance)
	$(DOCKER_RUN) $(ALPINE_IMAGE) \
		$(ACCEPTANCE_CMD)

.PHONY: alpine-3.6
alpine-3.6:
	$(call title,alpine:3.6 - build environment)
	docker build -t $(ALPINE_IMAGE) -f $(ENVS)/Dockerfile-alpine-3.6 .

## BUSYBOX #######################################################

# note: unit tests cannot be run with sh (busybox dosn't have bash by default)

# note: busybox by default will not have cacerts, so you will get TLS warnings (we want to test under these conditions)

.PHONY: acceptance-busybox-1.36
acceptance-busybox-1.36: busybox-1.36
	$(call title,busybox-1.36 - acceptance)
	$(DOCKER_RUN) $(BUSYBOX_IMAGE) \
		$(ACCEPTANCE_CMD)
	@echo "\n*** test note: you should see grype spit out a 'x509: certificate signed by unknown authority' error --this is expected ***"

.PHONY: busybox-1.36
busybox-1.36:
	$(call title,busybox-1.36 - build environment)
	docker build -t $(BUSYBOX_IMAGE) -f $(ENVS)/Dockerfile-busybox-1.36 .

## For CI ########################################################

.PHONY: cache.fingerprint
cache.fingerprint:
	$(call title,Install test fixture fingerprint)
	@find ./environments/* -type f -exec md5sum {} + | awk '{print $1}' | sort | tee /dev/stderr | md5sum | tee cache.fingerprint && echo "$(INSTALL_TEST_CACHE_BUSTER)" >> cache.fingerprint
