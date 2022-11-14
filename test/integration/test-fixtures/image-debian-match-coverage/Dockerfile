FROM golang@sha256:06b538f1c9d785537f4d24b0ee7297e8b2381dae954bd33c19513cc6465c4171
WORKDIR /go/src/github.com/anchore/test/
COPY golang/ ./
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o go-app .

FROM scratch
COPY --from=0 /go/src/github.com/anchore/test/go-app ./
COPY . .
