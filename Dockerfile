FROM gcr.io/distroless/static-debian11:debug AS build

FROM scratch
# needed for version check HTTPS request
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

# create the /tmp dir, which is needed for image content cache
WORKDIR /tmp

COPY grype /

ARG BUILD_DATE
ARG BUILD_VERSION
ARG VCS_REF
ARG VCS_URL

LABEL org.opencontainers.image.created=$BUILD_DATE
LABEL org.opencontainers.image.title="grype"
LABEL org.opencontainers.image.description="A vulnerability scanner for container images and filesystems"
LABEL org.opencontainers.image.source=$VCS_URL
LABEL org.opencontainers.image.revision=$VCS_REF
LABEL org.opencontainers.image.vendor="Anchore, Inc."
LABEL org.opencontainers.image.version=$BUILD_VERSION
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL io.artifacthub.package.readme-url="https://raw.githubusercontent.com/anchore/grype/main/README.md"
LABEL io.artifacthub.package.logo-url="https://user-images.githubusercontent.com/5199289/136855393-d0a9eef9-ccf1-4e2b-9d7c-7aad16a567e5.png"
LABEL io.artifacthub.package.license="Apache-2.0"

ENTRYPOINT ["/grype"]
