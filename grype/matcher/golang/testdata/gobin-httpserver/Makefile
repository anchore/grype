BINARY := binary
.DEFAULT_GOAL := $(BINARY)

.PHONY: clean
$(BINARY): $(wildcard *.go) go.mod
	go build -trimpath -o $(BINARY) .

clean:
	rm -f $(BINARY)
