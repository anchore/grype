FROM docker.io/golang:1.16@sha256:92ccbb6513249c08e582ca3eafc5c9176dbc5cbfe73af245542c5c78250e9b49
WORKDIR /go/src/github.com/anchore/test/
COPY golang/ ./
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o go-app .

FROM scratch
COPY --from=0 /go/src/github.com/anchore/test/go-app ./
COPY . .
