FROM golang:1.16
WORKDIR /go/src/github.com/anchore/test/
COPY golang/ ./
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o go-app .

FROM scratch
COPY --from=0 /go/src/github.com/anchore/test/go-app ./
COPY . .