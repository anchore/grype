BINARY := binary
.DEFAULT_GOAL := $(BINARY)

# always build an ELF binary: syft only extracts go symbols from ELF and Mach-O (not PE), so a
# native windows build would carry no symbols
export GOOS := linux

.PHONY: clean
$(BINARY): $(wildcard *.go) Makefile go.mod go.sum
	go build -trimpath -o $(BINARY) .

clean:
	rm -f $(BINARY)
