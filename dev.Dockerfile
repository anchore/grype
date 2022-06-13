FROM docker:latest

ENV GO_VERSION=1.18.2
ENV PATH=$PATH:/usr/local/go/bin:/usr/bin/env:/root/go/bin

WORKDIR /grype

COPY go.mod go.sum Makefile /grype/
COPY .github .github

RUN docker-entrypoint.sh && \
    apk update && \
    apk add make curl build-base bash ncurses openssl && \
    curl -OL https://golang.org/dl/go${GO_VERSION}.linux-amd64.tar.gz && \
    tar -C /usr/local -xf go${GO_VERSION}.linux-amd64.tar.gz && \
    go install github.com/go-delve/delve/cmd/dlv@latest && \
    # fix all line terminations in .sh scripts for windows
    find . -name "*.sh" -exec sed -i -e 's/\r$//' {} + && \
    make bootstrap
    