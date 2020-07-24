IMAGE = "centos:8"
IMAGE_CLEAN = $(shell echo $(IMAGE) | tr ":" "_")
grype_DIR = grype-reports
grype_REPORT = $(grype_DIR)/$(IMAGE_CLEAN).json
INLINE_DIR = inline-reports
INLINE_REPORT = $(INLINE_DIR)/$(IMAGE_CLEAN)-content-os.json

ifndef grype_DIR
	$(error grype_DIR is not set)
endif

ifndef INLINE_DIR
	$(error INLINE_DIR is not set)
endif

.PHONY: all
all: compare

.PHONY: compare
compare: $(INLINE_REPORT) $(grype_REPORT)
	docker build -t compare-grype:latest .
	docker run compare-grype:latest $(IMAGE)

$(INLINE_REPORT):
	echo "Creating $(INLINE_REPORT)..."
	mkdir -p $(INLINE_DIR)
	curl -s https://ci-tools.anchore.io/inline_scan-v0.7.0 | bash -s -- -p -r $(IMAGE)
	mv anchore-reports/* $(INLINE_DIR)/
	rmdir anchore-reports

$(grype_REPORT):
	echo "Creating $(grype_REPORT)..."
	mkdir -p $(grype_DIR)
	docker pull $(IMAGE)
	go run ../../main.go $(IMAGE) -o json > $(grype_REPORT)

.PHONY: clean
clean:
	rm -f $(INLINE_DIR)/*  $(grype_DIR)/*