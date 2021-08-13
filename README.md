# grype

[![Static Analysis + Unit + Integration](https://github.com/anchore/grype/workflows/Static%20Analysis%20+%20Unit%20+%20Integration/badge.svg)](https://github.com/anchore/grype/actions?query=workflow%3A%22Static+Analysis+%2B+Unit+%2B+Integration%22)
[![Acceptance](https://github.com/anchore/grype/workflows/Acceptance/badge.svg)](https://github.com/anchore/grype/actions?query=workflow%3AAcceptance)
[![Go Report Card](https://goreportcard.com/badge/github.com/anchore/grype)](https://goreportcard.com/report/github.com/anchore/grype)
[![GitHub release](https://img.shields.io/github/release/anchore/grype.svg)](https://github.com/anchore/grype/releases/latest)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/anchore/grype/blob/main/LICENSE)
[![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/anchore/grype.svg)](https://github.com/anchore/grype)

A vulnerability scanner for container images and filesystems. Easily [install the binary](#installation) to try it out. Works with [Syft](https://github.com/anchore/syft), the powerful SBOM (software bill of materials) tool for container images and filesystems.

![grype-demo](https://user-images.githubusercontent.com/590471/90276236-9868f300-de31-11ea-8068-4268b6b68529.gif)

### Features

- Scan the contents of a container image or filesystem to find known vulnerabilities.
- Find vulnerabilities for major operating system packages:
  - Alpine
  - Amazon Linux
  - BusyBox
  - CentOS
  - Debian
  - Distroless
  - Oracle Linux
  - Red Hat (RHEL)
  - Ubuntu
- Find vulnerabilities for language-specific packages:
  - Ruby (Gems)
  - Java (JAR, WAR, EAR, JPI, HPI)
  - JavaScript (NPM, Yarn)
  - Python (Egg, Wheel, Poetry, requirements.txt/setup.py files)
- Supports Docker and OCI image formats

If you encounter an issue, please [let us know using the issue tracker](https://github.com/anchore/grype/issues).

## Getting started

[Install the binary](#installation), and make sure that `grype` is available in your path. To scan for vulnerabilities in an image:

```
grype <image>
```

The above command scans for vulnerabilities that are visible in the container (i.e., the squashed representation of the image).
To include software from all image layers in the vulnerability scan, regardless of its presence in the final image, provide `--scope all-layers`:

```
grype <image> --scope all-layers
```

Grype can scan a variety of sources beyond those found in Docker.

```
# scan a container image archive (from the result of `docker image save ...`, `podman save ...`, or `skopeo copy` commands)
grype path/to/image.tar

# scan a directory
grype dir:path/to/dir
```

Use [Syft](https://github.com/anchore/syft) SBOMs for even faster vulnerability scanning in Grype:

```
# Just need to generate the SBOM once
syft <image> -o json > ./image-sbom.json

# Then scan for new vulnerabilities as frequently as needed
grype sbom:./image-sbom.json

# (You can also pipe the SBOM into Grype)
cat ./image-sbom.json | grype
```

Sources can be explicitly provided with a scheme:
```
docker:yourrepo/yourimage:tag          use images from the Docker daemon
docker-archive:path/to/yourimage.tar   use a tarball from disk for archives created from "docker save"
oci-archive:path/to/yourimage.tar      use a tarball from disk for OCI archives (from Skopeo or otherwise)
oci-dir:path/to/yourimage              read directly from a path on disk for OCI layout directories (from Skopeo or otherwise)
dir:path/to/yourproject                read directly from a path on disk (any directory)
registry:yourrepo/yourimage:tag        pull image directly from a registry (no container runtime required)
```

The output format for Grype is configurable as well:
```
grype <image> -o <format>
```

Where the `format`s available are:
- `table`: A columnar summary (default).
- `cyclonedx`: An XML report conforming to the [CycloneDX 1.2](https://cyclonedx.org/) specification.
- `json`: Use this to get as much information out of Grype as possible!
- `template`: Lets the user specify the output format. See [Using Templates](#using-templates) below.

### Using Templates

Grype lets you define custom output formats, using [Go templates](https://golang.org/pkg/text/template/). Here's how it works:

- Define your format as a Go template, and save this template as a file.

- Set the output format to "template" (`-o template`). 

- Specify the path to the template file (`-t ./path/to/custom.template`).

- Grype's template processing uses the same data models as the `json` output format — so if you're wondering what data is available as you author a template, you can use the output from `grype <image> -o json` as a reference.

**Example:** You could make Grype output data in CSV format by writing a Go template that renders CSV data and then running `grype <image> -o ~/path/to/csv.tmpl`.

Here's what the `csv.tmpl` file might look like:
```gotemplate
"Package","Version Installed","Vulnerability ID","Severity"
{{- range .Matches}}
"{{.Artifact.Name}}","{{.Artifact.Version}}","{{.Vulnerability.ID}}","{{.Vulnerability.Severity}}"
{{- end}}
```

Which would produce output like:
```text
"Package","Version Installed","Vulnerability ID","Severity"
"coreutils","8.30-3ubuntu2","CVE-2016-2781","Low"
"libc-bin","2.31-0ubuntu9","CVE-2016-10228","Negligible"
"libc-bin","2.31-0ubuntu9","CVE-2020-6096","Low"
...
```

### Grype's Database

Grype pulls a database of vulnerabilities derived from the publicly available [Anchore Feed Service](https://ancho.re/v1/service/feeds). This database is updated at the beginning of each scan, but an update can also be triggered manually.

```
grype db update
```

## Installation

**Recommended (macOS and Linux)**

```bash
# install the latest version to /usr/local/bin
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# install a specific version into a specific dir
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b <SOME_BIN_PATH> <RELEASE_VERSION>
```

**Homebrew (macOS)**

```bash
brew tap anchore/grype
brew install grype
```

## Shell Completion

Grype supplies shell completion through its CLI implementation ([cobra](https://github.com/spf13/cobra/blob/master/shell_completions.md)).
Generate the completion code for your shell by running one of the following commands:
* `grype completion <bash|fish>`
* `go run main.go completion <bash|fish>`

This will output a shell script to STDOUT, which can then be used as a completion script for Grype. Running one of the above commands with the
`-h` or `--help` flags will provide instructions on how to do that for your chosen shell.

Note: [Cobra has not yet released full ZSH support](https://github.com/spf13/cobra/issues/1226), but as soon as that gets released, we will add it here!

## Configuration

Configuration search paths:

- `.grype.yaml`
- `.grype/config.yaml`
- `~/.grype.yaml`
- `<XDG_CONFIG_HOME>/grype/config.yaml`

Configuration options (example values are the default):

```yaml
# enable/disable checking for application updates on startup
check-for-app-update: true

# same as --fail-on ; upon scanning, if a severity is found at or above the given severity then the return code will be 1
# default is unset which will skip this validation (options: negligible, low, medium, high, critical)
fail-on-severity: ''

# same as -o ; the output format of the vulnerability report (options: table, json, cyclonedx)
output: "table"

# same as -s ; the search space to look for packages (options: all-layers, squashed)
scope: "squashed"

# same as -q ; suppress all output (except for the vulnerability list)
quiet: false

db:
  # check for database updates on execution
  auto-update: true

  # location to write the vulnerability database cache
  cache-dir: "$XDG_CACHE_HOME/grype/db"

  # URL of the vulnerability database
  update-url: "https://toolbox-data.anchore.io/grype/databases/listing.json"

# options when pulling directly from a registry via the "registry:" scheme
registry:
  # skip TLS verification when communicating with the registry
  # GRYPE_REGISTRY_INSECURE_SKIP_TLS_VERIFY env var
  insecure-skip-tls-verify: false
  # use http instead of https when connecting to the registry
  # SYFT_REGISTRY_INSECURE_USE_HTTP env var
  insecure-use-http: false

  # credentials for specific registries
  auth:
    - # the URL to the registry (e.g. "docker.io", "localhost:5000", etc.)
      # GRYPE_REGISTRY_AUTH_AUTHORITY env var
      authority: ""
      # GRYPE_REGISTRY_AUTH_USERNAME env var
      username: ""
      # GRYPE_REGISTRY_AUTH_PASSWORD env var
      password: ""
      # note: token and username/password are mutually exclusive
      # GRYPE_REGISTRY_AUTH_TOKEN env var
      token: ""
    - ... # note, more credentials can be provided via config file only


log:
  # location to write the log file (default is not to have a log file)
  file: ""

  # the log level; note: detailed logging suppress the ETUI
  level: "error"

  # use structured logging
  structured: false
```

## Future plans

The following areas of potential development are currently being investigated:

- Support for allowlist, package mapping
- Accept alternative SBOM formats (CycloneDX, SPDX) as input
