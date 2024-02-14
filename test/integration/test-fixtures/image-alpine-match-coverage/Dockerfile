FROM cgr.dev/chainguard/go as builder

RUN go install github.com/google/ko@v0.15.1

FROM scratch
COPY . .
COPY --from=builder /root/go/bin/ko /ko
