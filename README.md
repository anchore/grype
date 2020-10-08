# grype

[![CircleCI](https://circleci.com/gh/anchore/grype.svg?style=svg)](https://circleci.com/gh/anchore/grype)
[![Go Report Card](https://goreportcard.com/badge/github.com/anchore/grype)](https://goreportcard.com/report/github.com/anchore/grype)
[![GitHub release](https://img.shields.io/github/release/anchore/grype.svg)](https://github.com/anchore/grype/releases/latest)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/anchore/grype/blob/main/LICENSE)

A vulnerability scanner for container images and filesystems. [Easily install the binary](#installation) to try it out.

![grype-demo](https://user-images.githubusercontent.com/590471/90276236-9868f300-de31-11ea-8068-4268b6b68529.gif)

**Features**

- Scan the contents of a container image or filesystem to find known vulnerabilities.
- Find vulnerabilities for major operating system packages
  - Alpine
  - BusyBox
  - CentOS / Red Hat
  - Debian
  - Ubuntu
- Find vulnerabilities for language-specific packages
  - Ruby (Bundler)
  - Java (JARs, etc)
  - JavaScript (NPM/Yarn)
  - Python (Egg/Wheel)
  - Python pip/requirements.txt/setup.py listings
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
grype path/to/dir
```

The output format for Grype is configurable as well:
```
grype <image> -o <format>
```

Where the `format`s available are:
- `json`: Use this to get as much information out of Grype as possible!
- `cyclonedx`: A XML report conforming to the [CycloneDX 1.2](https://cyclonedx.org/) specification.
- `table`: A columnar summary (default).

Grype pulls a database of vulnerabilities derived from the publicly available [Anchore Feed Service](https://ancho.re/v1/service/feeds). This database is updated at the beginning of each scan, but an update can also be triggered manually.

```
grype db update
```

## Installation

**Recommended**

```bash
# install the latest version to /usr/local/bin
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# install a specific version into a specific dir
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s <RELEASE_VERSION> -b <SOME_BIN_PATH>
```

**macOS**

```bash
brew tap anchore/grype
brew install grype
```

You may experience a "macOS cannot verify app is free from malware" error upon running Grype because it is not yet signed and notarized. You can override this using `xattr`.

```bash
xattr -rd com.apple.quarantine grype
```

## Shell Completion

Grype supplies shell completion through it's CLI implementation ([cobra](https://github.com/spf13/cobra/blob/master/shell_completions.md)).
Generate the completion code for your shell by running one of the following commands:
* `grype completion <bash|fish>`
* `go run main.go completion <bash|fish>`

This will output a shell script to STDOUT, which can then be used as a completion script for Grype. Running one of the above commands with the
`-h` or `--help` flags will provide instructions on how to do that for your chosen shell.

Note: [Cobra hs not yet released full ZSH support](https://github.com/spf13/cobra/issues/1226), but as soon as that gets released, we will add it here!

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
- Establish a stable interchange format w/Syft
- Accept SBOM (CycloneDX, Syft) as input instead of image/directory


