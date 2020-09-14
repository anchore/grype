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

> :warning: **This is pre-release software** and it may not work as expected. If you encounter an issue, please [let us know using the issue tracker](https://github.com/anchore/grype/issues).

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
# scan a docker image tar (from the result of "docker image save ... -o image.tar" command)
grype docker-archive://path/to/image.tar

# scan a directory
grype dir://path/to/dir
```

By default Grype shows a summary table, however, a more detailed `json` format is also available.

```
grype <image> -o json
```

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

## Configuration

Configuration search paths:

- `.grype.yaml`
- `.grype/config.yaml`
- `~/.grype.yaml`
- `<XDG_CONFIG_HOME>/grype/config.yaml`

Configuration options (example values are the default):

```yaml
# same as -o ; the output format of the vulnerability report (options: table, json)
output: "table"

# same as -s ; the search space to look for packages (options: all-layers, squashed)
scope: "squashed"

# same as -q ; suppress all output (except for the vulnerability list)
quiet: false

log:
  # use structured logging
  structured: false

  # the log level; note: detailed logging suppress the ETUI
  level: "error"

  # location to write the log file (default is not to have a log file)
  file: ""

# enable/disable checking for application updates on startup
check-for-app-update: true

db:
  # location to write the vulnerability database cache
  cache-dir: "$XDG_CACHE_HOME/grype/db"

  # URL of the vulnerability database
  update-url: "https://toolbox-data.anchore.io/grype/databases/listing.json"

  # check for database updates on execution
  auto-update: true
```

## Developing

There are a few useful things to know before diving into the codebase. This project depends on a few things being available like a vulnerability database, which you might want to create manually instead of retrieving a released version.

### Inspecting the database

The currently supported database provider is Sqlite3. Install `sqlite3` in your system and ensure that the `sqlite3` executable is available in your path. Ask `grype` about the location of the database, which will be different depending on the operating system:

```
$ go run main.go db status
Location:  /Users/alfredo/Library/Caches/grype/db
Built:  2020-07-31 08:18:29 +0000 UTC
Current DB Version:  1
Require DB Version:  1
Status: Valid
```

In this case (OSX), the database is located in the user's home directory. To verify the database filename, list that path:

```
$ ls -alh  /Users/alfredo/Library/Caches/grype/db
total 445392
drwxr-xr-x  4 alfredo  staff   128B Jul 31 09:27 .
drwxr-xr-x  3 alfredo  staff    96B Jul 31 09:27 ..
-rw-------  1 alfredo  staff   139B Jul 31 09:27 metadata.json
-rw-r--r--  1 alfredo  staff   217M Jul 31 09:27 vulnerability.db
```

Next, open the `vulnerability.db` with `sqlite3`:

```
$ sqlite3 /Users/alfredo/Library/Caches/grype/db/vulnerability.db
```

To make the reporting from Sqlite3 easier to read, enable the following:

```
sqlite> .mode column
sqlite> .headers on
```

List the tables:

```
sqlite> .tables
id                      vulnerability           vulnerability_metadata
```

In this example you retrieve a specific vulnerability from the `nvd` namespace:

```
sqlite> select * from vulnerability where (namespace="nvd" and package_name="libvncserver") limit 1;
id             record_source  package_name  namespace   version_constraint  version_format  cpes                                                         proxy_vulnerabilities
-------------  -------------  ------------  ----------  ------------------  --------------  -----------------------------------------------------------  ---------------------
CVE-2006-2450                 libvncserver  nvd         = 0.7.1             unknown         ["cpe:2.3:a:libvncserver:libvncserver:0.7.1:*:*:*:*:*:*:*"]  []
```

## Shell Completion
Grype supplies shell completion through it's CLI implementation ([cobra](https://github.com/spf13/cobra/blob/master/shell_completions.md)). 
Generate the completion code for your shell by running one of the following commands:
* `grype completion <bash|fish>`
* `go run main.go completion <bash|fish>`

This will output a shell script to STDOUT, which can then be used as a completion script for Grype. Running one of the above commands with the 
`-h` or `--help` flags will provide instructions on how to do that for your chosen shell.

Note: [Cobra hs not yet released full ZSH support](https://github.com/spf13/cobra/issues/1226), but as soon as that gets released, we will add it here!

## Future plans

The following areas of potential development are currently being investigated:

- Add CycloneDX to list of output formats
- Support for allowlist, package mapping
- Establish a stable interchange format w/Syft
- Accept SBOM (CycloneDX, Syft) as input instead of image/directory


