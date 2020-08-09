ifndef GRYPE_CMD
	GRYPE_CMD = go run ../../main.go
endif

IMAGE_CLEAN = $(shell echo $(COMPARE_IMAGE) | tr ":" "_")
GRYPE_DIR = grype-reports
GRYPE_REPORT = $(GRYPE_DIR)/$(IMAGE_CLEAN).json
INLINE_DIR = inline-reports
INLINE_REPORT = $(INLINE_DIR)/$(IMAGE_CLEAN)-content-os.json

ifndef GRYPE_DIR
	$(error GRYPE_DIR is not set)
endif

ifndef INLINE_DIR
	$(error INLINE_DIR is not set)
endif

.PHONY: all
.DEFAULT_GOAL :=
all: clean-grype
	./compare-all.sh

.PHONY: compare-image
compare-image: $(GRYPE_REPORT) $(INLINE_REPORT)
	./compare.py $(COMPARE_IMAGE)

.PHONY: gather-image
gather-image: $(GRYPE_REPORT) $(INLINE_REPORT)

$(INLINE_REPORT):
	echo "Creating $(INLINE_REPORT)..."
	mkdir -p $(INLINE_DIR)
	curl -s https://ci-tools.anchore.io/inline_scan-v0.7.0 | bash -s -- -p -r $(COMPARE_IMAGE)
	mv anchore-reports/* $(INLINE_DIR)/
	rmdir anchore-reports

$(GRYPE_REPORT):
	echo "Creating $(GRYPE_REPORT)..."
	mkdir -p $(GRYPE_DIR)
	$(GRYPE_CMD) $(COMPARE_IMAGE) -o json > $(GRYPE_REPORT)

.PHONY: clean
clean:
	rm -f $(INLINE_DIR)/*

.PHONY: clean-grype
clean-grype:
	rm -f $(GRYPE_DIR)/*

