<p align="center">
    <img src="https://user-images.githubusercontent.com/5199289/136855393-d0a9eef9-ccf1-4e2b-9d7c-7aad16a567e5.png" width="234">
</p>

[![Static Analysis + Unit + Integration](https://github.com/anchore/grype/workflows/Static%20Analysis%20+%20Unit%20+%20Integration/badge.svg)](https://github.com/anchore/grype/actions?query=workflow%3A%22Static+Analysis+%2B+Unit+%2B+Integration%22)
[![Acceptance](https://github.com/anchore/grype/workflows/Acceptance/badge.svg)](https://github.com/anchore/grype/actions?query=workflow%3AAcceptance)
[![Go Report Card](https://goreportcard.com/badge/github.com/anchore/grype)](https://goreportcard.com/report/github.com/anchore/grype)
[![GitHub release](https://img.shields.io/github/release/anchore/grype.svg)](https://github.com/anchore/grype/releases/latest)
[![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/anchore/grype.svg)](https://github.com/anchore/grype)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/anchore/grype/blob/main/LICENSE)
[![Slack Invite](https://img.shields.io/badge/Slack-Join-blue?logo=slack)](https://anchore.com/slack)

A vulnerability scanner for container images and filesystems. Easily [install the binary](#installation) to try it out. Works with [Syft](https://github.com/anchore/syft), the powerful SBOM (software bill of materials) tool for container images and filesystems.

![grype-demo](https://user-images.githubusercontent.com/590471/90276236-9868f300-de31-11ea-8068-4268b6b68529.gif)

## Features

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

## Installation

### Recommended

```bash
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
```

...or, you can specify a release version and destination directory for the installation:

```
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b <DESTINATION_DIR> <RELEASE_VERSION>
```

### Homebrew

```bash
brew tap anchore/grype
brew install grype
```

**Note**: Currently, Grype is built only for macOS and Linux.

## Getting started

[Install the binary](#installation), and make sure that `grype` is available in your path. To scan for vulnerabilities in an image:

```
grype <image>
```

The above command scans for vulnerabilities that are visible in the container (i.e., the squashed representation of the image). To include software from all image layers in the vulnerability scan, regardless of its presence in the final image, provide `--scope all-layers`:

```
grype <image> --scope all-layers
```

### Supported sources

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

### Output formats

The output format for Grype is configurable as well:
```
grype <image> -o <format>
```

Where the `format`s available are:
- `table`: A columnar summary (default).
- `cyclonedx`: An XML report conforming to the [CycloneDX 1.2](https://cyclonedx.org/) specification.
- `json`: Use this to get as much information out of Grype as possible!
- `template`: Lets the user specify the output format. See ["Using templates"](#using-templates) below.

### Using templates

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

### Gating on severity of vulnerabilities

You can have Grype exit with an error if any vulnerabilities are reported at or above the specified severity level. This comes in handy when using Grype within a script or CI pipeline. To do this, use the `--fail-on <severity>` CLI flag.

For example, here's how you could trigger a CI pipeline failure if any vulnerabilities are found in the `ubuntu:latest` image with a severity of "medium" or higher:

```
grype ubuntu:latest --fail-on medium
```

### Specifying matches to ignore

If you're seeing Grype report **false positives** or any other vulnerability matches that you just don't want to see, you can tell Grype to **ignore** matches by specifying one or more _"ignore rules"_ in your Grype configuration file (e.g. `~/.grype.yaml`). This causes Grype not to report any vulnerability matches that meet the criteria specified by any of your ignore rules.

Each rule can specify any combination of the following criteria:

- vulnerability ID (e.g. `"CVE-2008-4318"`)
- fix state (allowed values: `"fixed"`, `"not-fixed"`, `"wont-fix"`, or `"unknown"`)
- package name (e.g. `"libcurl"`)
- package version (e.g. `"1.5.1"`)
- package type (e.g. `"npm"`; these values are defined [here](https://github.com/anchore/syft/blob/main/syft/pkg/type.go#L10-L21))
- package location (e.g. `"/usr/local/lib/node_modules/**"`; supports glob patterns)

Here's an example `~/.grype.yaml` that demonstrates the expected format for ignore rules:

```yaml
ignore:
  
  # This is the full set of supported rule fields:
  - vulnerability: CVE-2008-4318
    fix-state: unknown
    package:
      name: libcurl
      version: 1.5.1
      type: npm
      location: "/usr/local/lib/node_modules/**"

  # We can make rules to match just by vulnerability ID:
  - vulnerability: CVE-2017-41432
  
  # ...or just by a single package field:
  - package:
      type: gem
```

Vulnerability matches will be ignored if **any** rules apply to the match. A rule is considered to apply to a given vulnerability match only if **all** fields specified in the rule apply to the vulnerability match.

When you run Grype while specifying ignore rules, the following happens to the vulnerability matches that are "ignored":

- Ignored matches are **completely hidden** from Grype's output, except for when using the `json` or `template` output formats; however, in these two formats, the ignored matches are **removed** from the existing `matches` array field, and they are placed in a new `ignoredMatches` array field. Each listed ignored match also has an additional field, `appliedIgnoreRules`, which is an array of any rules that caused Grype to ignore this vulnerability match.

- Ignored matches **do not** factor into Grype's exit status decision when using `--fail-on <severity>`. For instance, if a user specifies `--fail-on critical`, and all of the vulnerability matches found with a "critical" severity have been _ignored_, Grype will exit zero.

**Note:** Please continue to **[report](https://github.com/anchore/grype/issues/new/choose)** any false positives you see! Even if you can reliably filter out false positives using ignore rules, it's very helpful to the Grype community if we have as much knowledge about Grype's false positives as possible. This helps us continuously improve Grype!

### Showing only "fixed" vulnerabilities

If you only want Grype to report vulnerabilities **that have a confirmed fix**, you can use the `--only-fixed` flag. (This automatically adds [ignore rules](#specifying-matches-to-ignore) into Grype's configuration, such that vulnerabilities that aren't fixed will be ignored.)

For example, here's a scan of Alpine 3.10:

```
NAME          INSTALLED  FIXED-IN   VULNERABILITY   SEVERITY
apk-tools     2.10.6-r0  2.10.7-r0  CVE-2021-36159  Critical
libcrypto1.1  1.1.1k-r0             CVE-2021-3711   Critical
libcrypto1.1  1.1.1k-r0             CVE-2021-3712   High
libssl1.1     1.1.1k-r0             CVE-2021-3712   High
libssl1.1     1.1.1k-r0             CVE-2021-3711   Critical
```

...and here's the same scan, but adding the flag `--only-fixed`:

```
NAME       INSTALLED  FIXED-IN   VULNERABILITY   SEVERITY
apk-tools  2.10.6-r0  2.10.7-r0  CVE-2021-36159  Critical
```

## Grype's database

When Grype performs a scan for vulnerabilities, it does so using a vulnerability database that's stored on your local filesystem.

By default, Grype automatically manages this database for you. Grype checks for new updates to the vulnerability database to make sure that every scan uses up-to-date vulnerability information. This behavior is configurable. For more information, see the [Managing Grype's database](#managing-grypes-database) section.

### How database updates work

Grype's vulnerability database is a SQLite file, named `vulnerability.db`. Updates to the database are atomic: the entire database is replaced and then treated as "readonly" by Grype.

Grype's first step in a database update is discovering databases that are available for retrieval. Grype does this by requesting a "listing file" from a public endpoint:

`https://toolbox-data.anchore.io/grype/databases/listing.json`

The listing file contains entries for every database that's available for download.

Here's an example of an entry in the listing file:

```json
{
  "built": "2021-10-21T08:13:41Z",
  "version": 3,
  "url": "https://toolbox-data.anchore.io/grype/databases/vulnerability-db_v3_2021-10-21T08:13:41Z.tar.gz",
  "checksum": "sha256:8c99fb4e516f10b304f026267c2a73a474e2df878a59bf688cfb0f094bfe7a91"
}
```

With this information, Grype can select the correct database (the most recently built database with the current schema version), download the database, and verify the database's integrity using the listed `checksum` value.

### Managing Grype's database

> **Note:** During normal usage, _there is no need for users to manage Grype's database!_ Grype manages its database behind the scenes. However, for users that need more control, Grype provides options to manage the database more explicitly.

#### Local database cache directory

By default, the database is cached on the local filesystem in the directory `$XDG_CACHE_HOME/grype/db/<SCHEMA-VERSION>/`. For example, on macOS, the database would be stored in `~/Library/Caches/grype/db/3/`. (For more information on XDG paths, refer to the [XDG Base Directory Specification](https://specifications.freedesktop.org/basedir-spec/basedir-spec-latest.html).)

You can set the cache directory path using the environment variable `GRYPE_DB_CACHE_DIR`.

#### Offline and air-gapped environments

By default, Grype checks for a new database on every run, by making a network call over the Internet. You can tell Grype not to perform this check by setting the environment variable `GRYPE_DB_AUTO_UPDATE` to `false`.

As long as you place Grype's `vulnerability.db` and `metadata.json` files in the cache directory for the expected schema version, Grype has no need to access the network.

#### CLI commands for database management

Grype provides database-specific CLI commands for users that want to control the database from the command line. Here are some of the useful commands provided:

`grype db status` — report the current status of Grype's database (such as its location, build date, and checksum)

`grype db check` — see if updates are available for the database

`grype db update` — ensure the latest database has been downloaded to the cache directory (Grype performs this operation at the beginnign of every scan by default)

Find complete information on Grype's database commands by running `grype db --help`.

## Shell completion

Grype supplies shell completion through its CLI implementation ([cobra](https://github.com/spf13/cobra/blob/master/shell_completions.md)). Generate the completion code for your shell by running one of the following commands:

* `grype completion <bash|zsh|fish>`
* `go run main.go completion <bash|zsh|fish>`

This will output a shell script to STDOUT, which can then be used as a completion script for Grype. Running one of the above commands with the
`-h` or `--help` flags will provide instructions on how to do that for your chosen shell.

## Private Registry Authentication

Grype uses the [authn](https://github.com/google/go-containerregistry/tree/main/pkg/authn) package to solve for private registry access. 

The config file listed in the linked authn package is where your credentials are stored when authenticating with private registries via some command like `docker login`.

An example plain text `config.json` looks something like this:
```
// config.json

{
	"auths": {
		"registry.example.com": {
			"username": "AzureDiamond",
			"password": "hunter2"
		}
	}
}
```

If you want to see the volume mount example detailed simply via podman you can use this command to verify a single run where `config.json` is populated to authenticate to the registry your private image is stored:

`podman run -v ./config.json:/config/config.json -e "DOCKER_CONFIG=/config" anchore/syft:latest  <private_image>`

The below section shows a simple workflow on how to mount this config as a secret into a container on kubernetes.
1. Create a secret. The value of `config.json` is important. It refers to the specification outlined [here](https://github.com/google/go-containerregistry/tree/main/pkg/authn#the-config-file).

Here is and example of the `secret.yaml` file that the pod configuration will consume as a volume. The key value `config.json` is important. That will be the name of the file on mount into the running pod.
```
# secret.yaml

apiVersion: v1
kind: Secret
metadata:
  name: registry-config
  namespace: grype
data:
  config.json: <base64 encoded config.json>
```

`kubectl apply -f secret.yaml -n grype`

Note: if you have not done so, you can run `kubectl create namespace grype` to isolate this example.

2. Create your pod running grype. The env `DOCKER_CONFIG` is important because it advertises to the `authn` package where to look for the credential file. In the below example, setting `DOCKER_CONFIG=/config` informs the package that credentials can be found at `/config/config.json`. This is why we used `config.json` as the key for our secret. When mounted into containers the secrets' key is used as the filename.

The `volumeMounts` section mounts our secret to `/config`. The `volumes` section names our volume and sources the secret we created in step one as the file we will be mounting.
```
# pod.yaml

apiVersion: v1
kind: Pod
spec:
  containers:
    - image: anchore/grype:latest
      name: grype-private-registry-demo
      env:
        - name: DOCKER_CONFIG
          value: /config
      volumeMounts:
      - mountPath: /config
        name: registry-config
        readOnly: true
      args:
        - <private_image>
  volumes:
  - name: registry-config
    secret:
      secretName: registry-config
```

`kubectl apply -f pod.yaml -n grype`

3. The user can now run `kubectl logs grype-private-registry-demo`. The logs should show the grype vulnerability analysis for the `<private_image>` provided in the pod configuration.

Using the above information, users should be able to configure private registry access without having to interface or shim into the `grype` or `syft` configuration files. The will also not be dependent on a docker daemon, (or some other runtime software) for registry configuration and access.

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

# same as --file; write output report to a file (default is to write to stdout)
file: ""

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
  # GRYPE_REGISTRY_INSECURE_USE_HTTP env var
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
