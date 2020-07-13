IMAGE = "centos:8"
IMAGE_CLEAN = $(shell echo $(IMAGE) | tr ":" "_")
VULNSCAN_DIR = vulnscan-reports
VULNSCAN_REPORT = $(VULNSCAN_DIR)/$(IMAGE_CLEAN).json
INLINE_DIR = inline-reports
INLINE_REPORT = $(INLINE_DIR)/$(IMAGE_CLEAN)-content-os.json

.PHONY: bootstrap

all: compare

compare: $(INLINE_REPORT) $(VULNSCAN_REPORT)
	docker build -t compare-imgbom:latest .
	docker run compare-imgbom:latest $(IMAGE)

$(INLINE_REPORT):
	echo "Creating $(INLINE_REPORT)..."
	mkdir -p $(INLINE_DIR)
	curl -s https://ci-tools.anchore.io/inline_scan-v0.7.0 | bash -s -- -p -r $(IMAGE)
	mv anchore-reports/* $(INLINE_DIR)/
	rmdir anchore-reports

$(VULNSCAN_REPORT):
	echo "Creating $(VULNSCAN_REPORT)..."
	mkdir -p $(VULNSCAN_DIR)
	docker pull $(IMAGE)
	go run ../main.go centos:latest -o json > $(VULNSCAN_REPORT)
