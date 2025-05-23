<p align="center">
    <img alt="Grype logo" src="https://user-images.githubusercontent.com/5199289/136855393-d0a9eef9-ccf1-4e2b-9d7c-7aad16a567e5.png" width="234">
</p>

<p align="center">
    &nbsp;<a href="https://github.com/anchore/grype/actions?query=workflow%3A%22Static+Analysis+%2B+Unit+%2B+Integration%22"><img src="https://github.com/anchore/grype/workflows/Static%20Analysis%20+%20Unit%20+%20Integration/badge.svg" alt="Static Analysis + Unit + Integration"></a>&nbsp;
    &nbsp;<a href="https://github.com/anchore/grype/actions/workflows/validations.yaml"><img src="https://github.com/anchore/grype/workflows/Validations/badge.svg" alt="Validations"></a>&nbsp;
    &nbsp;<a href="https://goreportcard.com/report/github.com/anchore/grype"><img src="https://goreportcard.com/badge/github.com/anchore/grype" alt="Go Report Card"></a>&nbsp;
    &nbsp;<a href="https://github.com/anchore/grype/releases/latest"><img src="https://img.shields.io/github/release/anchore/grype.svg" alt="GitHub release"></a>&nbsp;
    &nbsp;<a href="https://github.com/anchore/grype"><img src="https://img.shields.io/github/go-mod/go-version/anchore/grype.svg" alt="GitHub go.mod Go version"></a>&nbsp;
    <br>
    &nbsp;<a href="https://github.com/anchore/grype/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License: Apache-2.0"></a>&nbsp;
    &nbsp;<a href="https://anchore.com/discourse"><img src="https://img.shields.io/badge/Discourse-Join-blue?logo=discourse" alt="Join our Discourse"></a>&nbsp;
    &nbsp;<a rel="me" href="https://fosstodon.org/@grype"><img src="https://img.shields.io/badge/Mastodon-Follow-blue?logoColor=white&amp;logo=mastodon" alt="Follow on Mastodon"></a>&nbsp;
    &nbsp;<a href="https://scorecard.dev/viewer/?uri=github.com/anchore/grype"><img src="https://api.securityscorecards.dev/projects/github.com/anchore/grype/badge" alt="OpenSSF Scorecard"></a>&nbsp;
    &nbsp;<a href="https://www.bestpractices.dev/projects/6708"><img src="https://www.bestpractices.dev/projects/6708/badge" alt="OpenSSF Best Practices"></a>&nbsp;
<p>

A vulnerability scanner for container images and filesystems. Easily [install the binary](#installation) to try it out. Works with [Syft](https://github.com/anchore/syft), the powerful SBOM (software bill of materials) tool for container images and filesystems.

### Join our community meetings!

- Calendar: https://calendar.google.com/calendar/u/0/r?cid=Y182OTM4dGt0MjRtajI0NnNzOThiaGtnM29qNEBncm91cC5jYWxlbmRhci5nb29nbGUuY29t
- Agenda: https://docs.google.com/document/d/1ZtSAa6fj2a6KRWviTn3WoJm09edvrNUp4Iz_dOjjyY8/edit?usp=sharing (join [this group](https://groups.google.com/g/anchore-oss-community) for write access)
- All are welcome!

For commercial support options with Syft or Grype, please [contact Anchore](https://get.anchore.com/contact/).

![grype-demo](https://user-images.githubusercontent.com/590471/90276236-9868f300-de31-11ea-8068-4268b6b68529.gif)

## Features

- Scan the contents of a container image or filesystem to find known vulnerabilities.
- Find vulnerabilities for major operating system packages:
  - Alpine
  - Amazon Linux
  - BusyBox
  - CentOS
  - CBL-Mariner
  - Debian
  - Distroless
  - Oracle Linux
  - Red Hat (RHEL)
  - Ubuntu
  - Wolfi
- Find vulnerabilities for language-specific packages:
  - Ruby (Gems)
  - Java (JAR, WAR, EAR, JPI, HPI)
  - JavaScript (NPM, Yarn)
  - Python (Egg, Wheel, Poetry, requirements.txt/setup.py files)
  - Dotnet (deps.json)
  - Golang (go.mod)
  - PHP (Composer)
  - Rust (Cargo)
- Supports Docker, OCI and [Singularity](https://github.com/sylabs/singularity) image formats.
- [OpenVEX](https://github.com/openvex) support for filtering and augmenting scanning results.

If you encounter an issue, please [let us know using the issue tracker](https://github.com/anchore/grype/issues).

## Installation

### Recommended

```bash
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
```
Install script options:
-	`-b`: Specify a custom installation directory (defaults to `./bin`)
-	`-d`: More verbose logging levels (`-d` for debug, `-dd` for trace)
-	`-v`: Verify the signature of the downloaded artifact before installation (requires [`cosign`](https://github.com/sigstore/cosign) to be installed)

### Chocolatey

The chocolatey distribution of grype is community-maintained and not distributed by the anchore team.

```bash
choco install grype -y
```

### Homebrew

```bash
brew tap anchore/grype
brew install grype
```

### MacPorts

On macOS, Grype can additionally be installed from the [community-maintained port](https://ports.macports.org/port/grype/) via MacPorts:

```bash
sudo port install grype
```

**Note**: Currently, Grype is built only for macOS and Linux.

### From source

See [DEVELOPING.md](DEVELOPING.md#native-development) for instructions to build and run from source.

### GitHub Actions

If you're using GitHub Actions, you can use our [Grype-based action](https://github.com/marketplace/actions/anchore-container-scan) to run vulnerability scans on your code or container images during your CI workflows.

## Verifying the artifacts

Checksums are applied to all artifacts, and the resulting checksum file is signed using cosign.

You need the following tool to verify signature:

- [Cosign](https://docs.sigstore.dev/cosign/system_config/installation/)

Verification steps are as follow:

1. Download the files you want, and the checksums.txt, checksums.txt.pem and checksums.txt.sig files from the [releases](https://github.com/anchore/grype/releases) page:

2. Verify the signature:

```shell
cosign verify-blob <path to checksum.txt> \
--certificate <path to checksums.txt.pem> \
--signature <path to checksums.txt.sig> \
--certificate-identity-regexp 'https://github\.com/anchore/grype/\.github/workflows/.+' \
--certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

3. Once the signature is confirmed as valid, you can proceed to validate that the SHA256 sums align with the downloaded artifact:

```shell
sha256sum --ignore-missing -c checksums.txt
```

## Getting started

[Install the binary](#installation), and make sure that `grype` is available in your path. To scan for vulnerabilities in an image:

```
grype <image>
```

The above command scans for vulnerabilities visible in the container (i.e., the squashed representation of the image). To include software from all image layers in the vulnerability scan, regardless of its presence in the final image, provide `--scope all-layers`:

```
grype <image> --scope all-layers
```

To run grype from a Docker container so it can scan a running container, use the following command:

```yml
docker run --rm \
--volume /var/run/docker.sock:/var/run/docker.sock \
--name Grype anchore/grype:latest \
$(ImageName):$(ImageTag)
```

## Supported sources

Grype can scan a variety of sources beyond those found in Docker.

```
# scan a container image archive (from the result of `docker image save ...`, `podman save ...`, or `skopeo copy` commands)
grype path/to/image.tar

# scan a Singularity Image Format (SIF) container
grype path/to/image.sif

# scan a directory
grype dir:path/to/dir
```

Sources can be explicitly provided with a scheme:

```
podman:yourrepo/yourimage:tag          use images from the Podman daemon
docker:yourrepo/yourimage:tag          use images from the Docker daemon
docker-archive:path/to/yourimage.tar   use a tarball from disk for archives created from "docker save"
oci-archive:path/to/yourimage.tar      use a tarball from disk for OCI archives (from Skopeo or otherwise)
oci-dir:path/to/yourimage              read directly from a path on disk for OCI layout directories (from Skopeo or otherwise)
singularity:path/to/yourimage.sif      read directly from a Singularity Image Format (SIF) container on disk
dir:path/to/yourproject                read directly from a path on disk (any directory)
file:path/to/yourfile                  read directly from a file on disk
sbom:path/to/syft.json                 read Syft JSON from path on disk
registry:yourrepo/yourimage:tag        pull image directly from a registry (no container runtime required)
```

If an image source is not provided and cannot be detected from the given reference it is assumed the image should be pulled from the Docker daemon.
If docker is not present, then the Podman daemon is attempted next, followed by reaching out directly to the image registry last.


This default behavior can be overridden with the `default-image-pull-source` configuration option (See [Configuration](https://github.com/anchore/grype#configuration) for more details).

Use SBOMs for even faster vulnerability scanning in Grype:

```
# Then scan for new vulnerabilities as frequently as needed
grype sbom:./sbom.json

# (You can also pipe the SBOM into Grype)
cat ./sbom.json | grype
```

Grype supports input of [Syft](https://github.com/anchore/syft), [SPDX](https://spdx.dev/), and [CycloneDX](https://cyclonedx.org/)
SBOM formats. If Syft has generated any of these file types, they should have the appropriate information to work properly with Grype.
It is also possible to use SBOMs generated by other tools with varying degrees of success. Two things that make Grype matching
more successful are the inclusion of CPE and Linux distribution information. If an SBOM does not include any CPE information, it
is possible to generate these based on package information using the `--add-cpes-if-none` flag. To specify a distribution,
use the `--distro <distro>:<version>` flag. A full example is:

```
grype --add-cpes-if-none --distro alpine:3.10 sbom:some-alpine-3.10.spdx.json
```

## Threat & Risk Prioritization

This section explains the columns and UI cues that help prioritize remediation efforts:

- **Severity**: String severity based on CVSS scores and indicate the significance of a vulnerability in levels.
  This balances concerns such as ease of exploitability, and the potential to affect 
  confidentiality, integrity, and availability of software and services.

- **EPSS**:
  [Exploit Prediction Scoring System](https://www.first.org/epss/model) is a metric expressing the likelihood
  that a vulnerability will be 
  exploited in the wild over the next 30 days (on a 0–1 scale); higher values signal a greater likelihood of 
  exploitation.
  The table output shows the EPSS percentile, a one-way transform of the EPSS score showing the 
  proportion of all scored vulnerabilities with an equal or lower probability.
  Percentiles linearize a heavily skewed distribution, making threshold choice (e.g. “only CVEs above the 
  90th percentile”) straightforward.

- **KEV Indicator**: Flags entries from CISA’s [Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
  --an authoritative list of flaws observed being exploited in the wild.

- **Risk Score**: A composite 0–100 metric calculated as:
  ```markdown
  risk = min(1, threat * average(severity)) * 100
  ```
  Where: 
  - `severity` is the average of all CVSS scores and string severity for a vulnerability (scaled between 0–1).
  - `threat` is the EPSS score (between 0–1). If the vulnerability is on the KEV list then `threat` is 
    `1.05`, or `1.1` if the vulnerability is associated with a ransomware campaign.
  This metric is one way to combine EPSS and CVSS suggested in the [EPSS user guide](https://www.first.org/epss/user-guide).

- **Suggested Fixes**: All possible fixes for a package are listed, however, when multiple fixes are available, we de-emphasize all 
  upgrade paths except for the minimal upgrade path (which highlights the smallest, safest version bump).

Results default to sorting by Risk Score and can be overridden with `--sort-by <value>`:

- `severity`: sort by severity
- `epss`: sort by EPSS percentile (aka, "threat")
- `risk`: sort by risk score
- `kev`: just like risk, except that KEV entries are always above non-KEV entries
- `package`: sort by package name, version, type
- `vulnerability`: sort by vulnerability ID

### Supported versions

Software updates are always applied to the latest version of Grype; fixes are not backported to any previous versions of Grype.

In terms of database updates, any version of Grype before v0.51.0 (Oct 2022, before schema v5) will not receive
vulnerability database updates. You can still build vulnerability databases for unsupported Grype releases by using previous
releases of [vunnel](https://github.com/anchore/vunnel) to gather the upstream data and [grype-db](https://github.com/anchore/grype-db)
to build databases for unsupported schemas.

Only the latest database schema is considered to be supported. When a new database schema is introduced then the one it replaces is
marked as deprecated. Deprecated schemas will continue to receive updates for at least one year after they are marked
as deprecated at which point they will no longer be supported.

### Working with attestations
Grype supports scanning SBOMs as input via stdin. Users can use [cosign](https://github.com/sigstore/cosign) to verify attestations
with an SBOM as its content to scan an image for vulnerabilities:
```
COSIGN_EXPERIMENTAL=1 cosign verify-attestation caphill4/java-spdx-tools:latest \
| jq -r .payload \
| base64 --decode \
| jq -r .predicate.Data \
| grype
```

### Vulnerability Summary

#### Basic Grype Vulnerability Data Shape

```json
 {
  "vulnerability": {
    ...
  },
  "relatedVulnerabilities": [
    ...
  ],
  "matchDetails": [
    ...
  ],
  "artifact": {
    ...
  }
}
```

- **Vulnerability**: All information on the specific vulnerability that was directly matched on (e.g. ID, severity, CVSS score, fix information, links for more information)
- **RelatedVulnerabilities**: Information pertaining to vulnerabilities found to be related to the main reported vulnerability. Maybe the vulnerability we matched on was a GitHub Security Advisory, which has an upstream CVE (in the authoritative national vulnerability database). In these cases we list the upstream vulnerabilities here.
- **MatchDetails**: This section tries to explain what we searched for while looking for a match and exactly what details on the package and vulnerability that lead to a match.
- **Artifact**: This is a subset of the information that we know about the package (when compared to the [Syft](https://github.com/anchore/syft) json output, we summarize the metadata section).
  This has information about where within the container image or directory we found the package, what kind of package it is, licensing info, pURLs, CPEs, etc.

### Excluding file paths

Grype can exclude files and paths from being scanned within a source by using glob expressions
with one or more `--exclude` parameters:

```
grype <source> --exclude './out/**/*.json' --exclude /etc
```

**Note:** in the case of _image scanning_, since the entire filesystem is scanned it is
possible to use absolute paths like `/etc` or `/usr/**/*.txt` whereas _directory scans_
exclude files _relative to the specified directory_. For example: scanning `/usr/foo` with
`--exclude ./package.json` would exclude `/usr/foo/package.json` and `--exclude '**/package.json'`
would exclude all `package.json` files under `/usr/foo`. For _directory scans_,
it is required to begin path expressions with `./`, `*/`, or `**/`, all of which
will be resolved _relative to the specified scan directory_. Keep in mind, your shell
may attempt to expand wildcards, so put those parameters in single quotes, like:
`'**/*.json'`.

### External Sources

Grype can be configured to incorporate external data sources for added fidelity in vulnerability matching. This
feature is currently disabled by default. To enable this feature add the following to the grype config:

```yaml
external-sources:
  enable: true
  maven:
    search-upstream-by-sha1: true
    base-url: https://search.maven.org/solrsearch/select
    rate-limit: 300ms # Time between Maven API requests
```

You can also configure the base-url if you're using another registry as your maven endpoint.

The rate at which Maven API requests are made can be configured to match your environment's requirements. The default is 300ms between requests.

### Output formats

The output format for Grype is configurable as well:

```
grype <image> -o <format>
```

Where the formats available are:

- `table`: A columnar summary (default).
- `cyclonedx`: An XML report conforming to the [CycloneDX 1.6 specification](https://cyclonedx.org/specification/overview/).
- `cyclonedx-json`: A JSON report conforming to the [CycloneDX 1.6 specification](https://cyclonedx.org/specification/overview/).
- `json`: Use this to get as much information out of Grype as possible!
- `sarif`: Use this option to get a [SARIF](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) report (Static Analysis Results Interchange Format)
- `template`: Lets the user specify the output format. See ["Using templates"](#using-templates) below.

### Using templates

Grype lets you define custom output formats, using [Go templates](https://golang.org/pkg/text/template/). Here's how it works:

- Define your format as a Go template, and save this template as a file.

- Set the output format to "template" (`-o template`).

- Specify the path to the template file (`-t ./path/to/custom.template`).

- Grype's template processing uses the same data models as the `json` output format — so if you're wondering what data is available as you author a template, you can use the output from `grype <image> -o json` as a reference.

**Please note:** Templates can access information about the system they are running on, such as environment variables. You should never run untrusted templates.

There are several example templates in the [templates](https://github.com/anchore/grype/tree/main/templates) directory in the Grype source which can serve as a starting point for a custom output format. For example, [csv.tmpl](https://github.com/anchore/grype/blob/main/templates/csv.tmpl) produces a vulnerability report in CSV (comma separated value) format:

```text
"Package","Version Installed","Vulnerability ID","Severity"
"coreutils","8.30-3ubuntu2","CVE-2016-2781","Low"
"libc-bin","2.31-0ubuntu9","CVE-2016-10228","Negligible"
"libc-bin","2.31-0ubuntu9","CVE-2020-6096","Low"
...
```

You can also find the template for the default "table" output format in the same place.

Grype also includes a vast array of utility templating functions from [sprig](http://masterminds.github.io/sprig/) apart from the default golang [text/template](https://pkg.go.dev/text/template#hdr-Functions) to allow users to customize the output from Grype.

### Gating on severity of vulnerabilities

You can have Grype exit with an error if any vulnerabilities are reported at or above the specified severity level. This comes in handy when using Grype within a script or CI pipeline. To do this, use the `--fail-on <severity>` CLI flag.

For example, here's how you could trigger a CI pipeline failure if any vulnerabilities are found in the `ubuntu:latest` image with a severity of "medium" or higher:

```
grype ubuntu:latest --fail-on medium
```

**Note:** Grype returns exit code `2` on vulnerability errors.

### Specifying matches to ignore

If you're seeing Grype report **false positives** or any other vulnerability matches that you just don't want to see, you can tell Grype to **ignore** matches by specifying one or more _"ignore rules"_ in your Grype configuration file (e.g. `~/.grype.yaml`). This causes Grype not to report any vulnerability matches that meet the criteria specified by any of your ignore rules.

Each rule can specify any combination of the following criteria:

- vulnerability ID (e.g. `"CVE-2008-4318"`)
- namespace (e.g. `"nvd"`)
- fix state (allowed values: `"fixed"`, `"not-fixed"`, `"wont-fix"`, or `"unknown"`)
- package name (e.g. `"libcurl"`)
- package version (e.g. `"1.5.1"`)
- package language (e.g. `"python"`; these values are defined [here](https://github.com/anchore/syft/blob/main/syft/pkg/language.go#L14-L23))
- package type (e.g. `"npm"`; these values are defined [here](https://github.com/anchore/syft/blob/main/syft/pkg/type.go#L10-L24))
- package location (e.g. `"/usr/local/lib/node_modules/**"`; supports glob patterns)

Here's an example `~/.grype.yaml` that demonstrates the expected format for ignore rules:

```yaml
ignore:
  # This is the full set of supported rule fields:
  - vulnerability: CVE-2008-4318
    fix-state: unknown
    # VEX fields apply when Grype reads vex data:
    vex-status: not_affected
    vex-justification: vulnerable_code_not_present
    package:
      name: libcurl
      version: 1.5.1
      type: npm
      location: "/usr/local/lib/node_modules/**"

  # We can make rules to match just by vulnerability ID:
  - vulnerability: CVE-2014-54321

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

If you want Grype to only report vulnerabilities **that do not have a confirmed fix**, you can use the `--only-notfixed` flag. Alternatively, you can use the `--ignore-states` flag to filter results for vulnerabilities with specific states such as `wont-fix` (see `--help` for a list of valid fix states). These flags automatically add [ignore rules](#specifying-matches-to-ignore) into Grype's configuration, such that vulnerabilities which are fixed, or will not be fixed, will be ignored.

## VEX Support

Grype can use VEX (Vulnerability Exploitability Exchange) data to filter false
positives or provide additional context, augmenting matches. When scanning a
container image, you can use the `--vex` flag to point to one or more
[OpenVEX](https://github.com/openvex) documents.

VEX statements relate a product (a container image), a vulnerability, and a VEX
status to express an assertion of the vulnerability's impact. There are four
[VEX statuses](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md#status-labels):
`not_affected`, `affected`, `fixed` and `under_investigation`.

Here is an example of a simple OpenVEX document. (tip: use
[`vexctl`](https://github.com/openvex/vexctl) to generate your own documents).

```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://openvex.dev/docs/public/vex-d4e9020b6d0d26f131d535e055902dd6ccf3e2088bce3079a8cd3588a4b14c78",
  "author": "A Grype User <jdoe@example.com>",
  "timestamp": "2023-07-17T18:28:47.696004345-06:00",
  "version": 1,
  "statements": [
    {
      "vulnerability": {
        "name": "CVE-2023-1255"
      },
      "products": [
        {
          "@id": "pkg:oci/alpine@sha256%3A124c7d2707904eea7431fffe91522a01e5a861a624ee31d03372cc1d138a3126",
          "subcomponents": [
            { "@id": "pkg:apk/alpine/libssl3@3.0.8-r3" },
            { "@id": "pkg:apk/alpine/libcrypto3@3.0.8-r3" }
          ]
        }
      ],
      "status": "fixed"
    }
  ]
}
```

By default, Grype will use any statements in specified VEX documents with a
status of `not_affected` or `fixed` to move matches to the ignore set.

Any matches ignored as a result of VEX statements are flagged when using
`--show-suppressed`:

```
libcrypto3  3.0.8-r3   3.0.8-r4   apk   CVE-2023-1255  Medium (suppressed by VEX)
```

Statements with an `affected` or `under_investigation` status will only be
considered to augment the result set when specifically requested using the
`GRYPE_VEX_ADD` environment variable or in a configuration file.


### VEX Ignore Rules

Ignore rules can be written to control how Grype honors VEX statements. For
example, to configure Grype to only act on VEX statements when the justification is `vulnerable_code_not_present`, you can write a rule like this:

```yaml
---
ignore:
  - vex-status: not_affected
    vex-justification: vulnerable_code_not_present
```

See the [list of justifications](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md#status-justifications) for details. You can mix `vex-status` and `vex-justification`
with other ignore rule parameters.

## Grype's database

When Grype performs a scan for vulnerabilities, it does so using a vulnerability database that's stored on your local filesystem, which is constructed by pulling data from a variety of publicly available vulnerability data sources. These sources include:

- Alpine Linux SecDB: https://secdb.alpinelinux.org/
- Amazon Linux ALAS: https://alas.aws.amazon.com/AL2/alas.rss
- Chainguard SecDB: https://packages.cgr.dev/chainguard/security.json
- Debian Linux CVE Tracker: https://security-tracker.debian.org/tracker/data/json
- GitHub Security Advisories (GHSAs): https://github.com/advisories
- National Vulnerability Database (NVD): https://nvd.nist.gov/vuln/data-feeds
- Oracle Linux OVAL: https://linux.oracle.com/security/oval/
- RedHat Linux Security Data: https://access.redhat.com/hydra/rest/securitydata/
- RedHat RHSAs: https://www.redhat.com/security/data/oval/
- SUSE Linux OVAL: https://ftp.suse.com/pub/projects/security/oval/
- Ubuntu Linux Security: https://people.canonical.com/~ubuntu-security/
- Wolfi SecDB: https://packages.wolfi.dev/os/security.json

By default, Grype automatically manages this database for you. Grype checks for new updates to the vulnerability database to make sure that every scan uses up-to-date vulnerability information. This behavior is configurable. For more information, see the [Managing Grype's database](#managing-grypes-database) section.

### How database updates work

Grype's vulnerability database is a SQLite file, named `vulnerability.db`. Updates to the database are atomic: the entire database is replaced and then treated as "readonly" by Grype.

Grype's first step in a database update is discovering databases that are available for retrieval. Grype does this by requesting a "latest database file" from a public endpoint:

https://grype.anchore.io/databases/v6/latest.json

The latest database file contains an entry for the most recent database available for download.

Here's an example of an entry in the latest database file:

```json
{
  "status": "active",
  "schemaVersion": "6.0.0",
  "built": "2025-02-11T04:06:41Z",
  "path": "vulnerability-db_v6.0.0_2025-02-11T01:30:51Z_1739246801.tar.zst",
  "checksum": "sha256:79bfa04265c5a32d21773ad0da1bda13c31e932fa1e1422db635c8d714038868"
}
```

With this information, Grype can find the most recently built database with the current schema version, download the database, and verify the database's integrity using the `checksum` value.

### Managing Grype's database

> **Note:** During normal usage, _there is no need for users to manage Grype's database!_ Grype manages its database behind the scenes. However, for users that need more control, Grype provides options to manage the database more explicitly.

#### Local database cache directory

By default, the database is cached on the local filesystem in the directory `$XDG_CACHE_HOME/grype/db/<SCHEMA-VERSION>/`. For example, on macOS, the database would be stored in `~/Library/Caches/grype/db/6/`. (For more information on XDG paths, refer to the [XDG Base Directory Specification](https://specifications.freedesktop.org/basedir-spec/basedir-spec-latest.html).)

You can set the cache directory path using the environment variable `GRYPE_DB_CACHE_DIR`. If setting that variable alone does not work, then the `TMPDIR` environment variable might also need to be set.

#### Data staleness

Grype needs up-to-date vulnerability information to provide accurate matches. By default, it will fail execution if the local database was not built in the last 5 days. The data staleness check is configurable via the environment variable `GRYPE_DB_MAX_ALLOWED_BUILT_AGE` and `GRYPE_DB_VALIDATE_AGE` or the field `max-allowed-built-age` and `validate-age`, under `db`. It uses [golang's time duration syntax](https://pkg.go.dev/time#ParseDuration). Set `GRYPE_DB_VALIDATE_AGE` or `validate-age` to `false` to disable staleness check.

#### Offline and air-gapped environments

By default, Grype checks for a new database on every run, by making a network request over the internet.
You can tell Grype not to perform this check by setting the environment variable `GRYPE_DB_AUTO_UPDATE` to `false`.

As long as you place Grype's `vulnerability.db` and `import.json` files in the cache directory for the expected schema version, Grype has no need to access the network.
Additionally, you can get a reference to the latest database archive for download from the `grype db list` command in an online environment, download the database archive, transfer it to your offline environment, and use `grype db import <db-archive-path>` to use the given database in an offline capacity.

If you would like to distribute your own Grype databases internally without needing to use `db import` manually you can leverage Grype's DB update mechanism. To do this you can craft your own `latest.json` file similar to the public "latest database file" and change the download URL to point to an internal endpoint (e.g. a private S3 bucket, an internal file server, etc.). Any internal installation of Grype can receive database updates automatically by configuring the `db.update-url` (same as the `GRYPE_DB_UPDATE_URL` environment variable) to point to the hosted `latest.json` file you've crafted.

#### CLI commands for database management

Grype provides database-specific CLI commands for users that want to control the database from the command line. Here are some of the useful commands provided:

`grype db status` — report the current status of Grype's database (such as its location, build date, and checksum)

`grype db check` — see if updates are available for the database

`grype db update` — ensure the latest database has been downloaded to the cache directory (Grype performs this operation at the beginning of every scan by default)

`grype db list` — download the latest database file configured at `db.update-url` and show the database available for download

`grype db import` — provide grype with a database archive to explicitly use (useful for offline DB updates)

`grype db providers` - provides a detailed list of database providers

Find complete information on Grype's database commands by running `grype db --help`.

## Shell completion

Grype supplies shell completion through its CLI implementation ([cobra](https://github.com/spf13/cobra/blob/master/shell_completions.md)). Generate the completion code for your shell by running one of the following commands:

- `grype completion <bash|zsh|fish>`
- `go run ./cmd/grype completion <bash|zsh|fish>`

This will output a shell script to STDOUT, which can then be used as a completion script for Grype. Running one of the above commands with the
`-h` or `--help` flags will provide instructions on how to do that for your chosen shell.

## Private Registry Authentication

### Local Docker Credentials

When a container runtime is not present, grype can still utilize credentials configured in common credential sources (such as `~/.docker/config.json`).
It will pull images from private registries using these credentials. The config file is where your credentials are stored when authenticating with private registries via some command like `docker login`.
For more information see the `go-containerregistry` [documentation](https://github.com/google/go-containerregistry/tree/main/pkg/authn).

An example `config.json` looks something like this:

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

You can run the following command as an example. It details the mount/environment configuration a container needs to access a private registry:

`docker run -v ./config.json:/config/config.json -e "DOCKER_CONFIG=/config" anchore/grype:latest <private_image>`

### Docker Credentials in Kubernetes

The below section shows a simple workflow on how to mount this config file as a secret into a container on kubernetes.

1.  Create a secret. The value of `config.json` is important. It refers to the specification detailed [here](https://github.com/google/go-containerregistry/tree/main/pkg/authn#the-config-file).
    Below this section is the `secret.yaml` file that the pod configuration will consume as a volume.
    The key `config.json` is important. It will end up being the name of the file when mounted into the pod.
    ``` # secret.yaml

        apiVersion: v1
        kind: Secret
        metadata:
          name: registry-config
          namespace: grype
        data:
          config.json: <base64 encoded config.json>
        ```

        `kubectl apply -f secret.yaml`

2.  Create your pod running grype. The env `DOCKER_CONFIG` is important because it advertises where to look for the credential file.
    In the below example, setting `DOCKER_CONFIG=/config` informs grype that credentials can be found at `/config/config.json`.
    This is why we used `config.json` as the key for our secret. When mounted into containers the secrets' key is used as the filename.
    The `volumeMounts` section mounts our secret to `/config`. The `volumes` section names our volume and leverages the secret we created in step one.
    ``` # pod.yaml

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

        `kubectl apply -f pod.yaml`

3.  The user can now run `kubectl logs grype-private-registry-demo`. The logs should show the grype analysis for the `<private_image>` provided in the pod configuration.

Using the above information, users should be able to configure private registry access without having to do so in the `grype` or `syft` configuration files.
They will also not be dependent on a docker daemon, (or some other runtime software) for registry configuration and access.

## Configuration

Default configuration search paths (see all with `grype config locations`):

- `.grype.yaml`
- `.grype/config.yaml`
- `~/.grype.yaml`
- `<XDG_CONFIG_HOME>/grype/config.yaml`

Use `grype config` to print a sample config file to stdout.
Use `grype config --load` to print the current config after loading all values to stdout.

You can specify files directly using the `--config` / `-c` flags (or environment variable `GRYPE_CONFIG`) to provide your own configuration files/paths:

```shell
# Using the flag
grype <image> -c /path/to/config.yaml
# Or using the environment variable
GRYPE_CONFIG=/path/to/config.yaml grype <image>
```

Configuration options (example values are the default):

```yaml
# the output format of the vulnerability report (options: table, template, json, cyclonedx)
# when using template as the output type, you must also provide a value for 'output-template-file' (env: GRYPE_OUTPUT)
output: 'table'

# if using template output, you must provide a path to a Go template file
# see https://github.com/anchore/grype#using-templates for more information on template output
# the default path to the template file is the current working directory
# output-template-file: .grype/html.tmpl
#
# write output report to a file (default is to write to stdout) (env: GRYPE_FILE)
file: ''

# pretty-print JSON output (env: GRYPE_PRETTY)
pretty: false

# distro to match against in the format: <distro>:<version> (env: GRYPE_DISTRO)
distro: ''

# generate CPEs for packages with no CPE data (env: GRYPE_ADD_CPES_IF_NONE)
add-cpes-if-none: false

# specify the path to a Go template file (requires 'template' output to be selected) (env: GRYPE_OUTPUT_TEMPLATE_FILE)
output-template-file: ''

# enable/disable checking for application updates on startup (env: GRYPE_CHECK_FOR_APP_UPDATE)
check-for-app-update: true

# ignore matches for vulnerabilities that are not fixed (env: GRYPE_ONLY_FIXED)
only-fixed: false

# ignore matches for vulnerabilities that are fixed (env: GRYPE_ONLY_NOTFIXED)
only-notfixed: false

# ignore matches for vulnerabilities with specified comma separated fix states, options=[fixed not-fixed unknown wont-fix] (env: GRYPE_IGNORE_WONTFIX)
ignore-wontfix: ''

# an optional platform specifier for container image sources (e.g. 'linux/arm64', 'linux/arm64/v8', 'arm64', 'linux') (env: GRYPE_PLATFORM)
platform: ''

# upon scanning, if a severity is found at or above the given severity then the return code will be 1
# default is unset which will skip this validation (options: negligible, low, medium, high, critical) (env: GRYPE_FAIL_ON_SEVERITY)
fail-on-severity: ''

# show suppressed/ignored vulnerabilities in the output (only supported with table output format) (env: GRYPE_SHOW_SUPPRESSED)
show-suppressed: false

# orient results by CVE instead of the original vulnerability ID when possible (env: GRYPE_BY_CVE)
by-cve: false

# sort the match results with the given strategy, options=[package severity epss risk kev vulnerability] (env: GRYPE_SORT_BY)
sort-by: 'risk'

# same as --name; set the name of the target being analyzed (env: GRYPE_NAME)
name: ''

# allows users to specify which image source should be used to generate the sbom
# valid values are: registry, docker, podman (env: GRYPE_DEFAULT_IMAGE_PULL_SOURCE)
default-image-pull-source: ''

search:
  # selection of layers to analyze, options=[squashed all-layers] (env: GRYPE_SEARCH_SCOPE)
  scope: 'squashed'

  # search within archives that do not contain a file index to search against (tar, tar.gz, tar.bz2, etc)
  # note: enabling this may result in a performance impact since all discovered compressed tars will be decompressed
  # note: for now this only applies to the java package cataloger (env: GRYPE_SEARCH_UNINDEXED_ARCHIVES)
  unindexed-archives: false

  # search within archives that do contain a file index to search against (zip)
  # note: for now this only applies to the java package cataloger (env: GRYPE_SEARCH_INDEXED_ARCHIVES)
  indexed-archives: true

# A list of vulnerability ignore rules, one or more property may be specified and all matching vulnerabilities will be ignored.
# This is the full set of supported rule fields:
#   - vulnerability: CVE-2008-4318
#     fix-state: unknown
#     package:
#       name: libcurl
#       version: 1.5.1
#       type: npm
#       location: "/usr/local/lib/node_modules/**"
#
# VEX fields apply when Grype reads vex data:
#   - vex-status: not_affected
#     vex-justification: vulnerable_code_not_present
ignore: []

# a list of globs to exclude from scanning, for example:
#   - '/etc/**'
#   - './out/**/*.json'
# same as --exclude (env: GRYPE_EXCLUDE)
exclude: []

external-sources:
  # enable Grype searching network source for additional information (env: GRYPE_EXTERNAL_SOURCES_ENABLE)
  enable: false

  maven:
    # search for Maven artifacts by SHA1 (env: GRYPE_EXTERNAL_SOURCES_MAVEN_SEARCH_MAVEN_UPSTREAM)
    search-maven-upstream: true

    # base URL of the Maven repository to search (env: GRYPE_EXTERNAL_SOURCES_MAVEN_BASE_URL)
    base-url: 'https://search.maven.org/solrsearch/select'

    # (env: GRYPE_EXTERNAL_SOURCES_MAVEN_RATE_LIMIT)
    rate-limit: 300ms

match:
  java:
    # use CPE matching to find vulnerabilities (env: GRYPE_MATCH_JAVA_USING_CPES)
    using-cpes: false

  jvm:
    # (env: GRYPE_MATCH_JVM_USING_CPES)
    using-cpes: true

  dotnet:
    # use CPE matching to find vulnerabilities (env: GRYPE_MATCH_DOTNET_USING_CPES)
    using-cpes: false

  golang:
    # use CPE matching to find vulnerabilities (env: GRYPE_MATCH_GOLANG_USING_CPES)
    using-cpes: false

    # use CPE matching to find vulnerabilities for the Go standard library (env: GRYPE_MATCH_GOLANG_ALWAYS_USE_CPE_FOR_STDLIB)
    always-use-cpe-for-stdlib: true

    # allow comparison between main module pseudo-versions (e.g. v0.0.0-20240413-2b432cf643...) (env: GRYPE_MATCH_GOLANG_ALLOW_MAIN_MODULE_PSEUDO_VERSION_COMPARISON)
    allow-main-module-pseudo-version-comparison: false

  javascript:
    # use CPE matching to find vulnerabilities (env: GRYPE_MATCH_JAVASCRIPT_USING_CPES)
    using-cpes: false

  python:
    # use CPE matching to find vulnerabilities (env: GRYPE_MATCH_PYTHON_USING_CPES)
    using-cpes: false

  ruby:
    # use CPE matching to find vulnerabilities (env: GRYPE_MATCH_RUBY_USING_CPES)
    using-cpes: false

  rust:
    # use CPE matching to find vulnerabilities (env: GRYPE_MATCH_RUST_USING_CPES)
    using-cpes: false

  stock:
    # use CPE matching to find vulnerabilities (env: GRYPE_MATCH_STOCK_USING_CPES)
    using-cpes: true


registry:
  # skip TLS verification when communicating with the registry (env: GRYPE_REGISTRY_INSECURE_SKIP_TLS_VERIFY)
  insecure-skip-tls-verify: false

  # use http instead of https when connecting to the registry (env: GRYPE_REGISTRY_INSECURE_USE_HTTP)
  insecure-use-http: false

  # Authentication credentials for specific registries. Each entry describes authentication for a specific authority:
  # -   authority: the registry authority URL the URL to the registry (e.g. "docker.io", "localhost:5000", etc.) (env: SYFT_REGISTRY_AUTH_AUTHORITY)
  #     username: a username if using basic credentials (env: SYFT_REGISTRY_AUTH_USERNAME)
  #     password: a corresponding password (env: SYFT_REGISTRY_AUTH_PASSWORD)
  #     token: a token if using token-based authentication, mutually exclusive with username/password (env: SYFT_REGISTRY_AUTH_TOKEN)
  #     tls-cert: filepath to the client certificate used for TLS authentication to the registry (env: SYFT_REGISTRY_AUTH_TLS_CERT)
  #     tls-key: filepath to the client key used for TLS authentication to the registry (env: SYFT_REGISTRY_AUTH_TLS_KEY)
  auth: []

  # filepath to a CA certificate (or directory containing *.crt, *.cert, *.pem) used to generate the client certificate (env: GRYPE_REGISTRY_CA_CERT)
  ca-cert: ''

# a list of VEX documents to consider when producing scanning results (env: GRYPE_VEX_DOCUMENTS)
vex-documents: []

# VEX statuses to consider as ignored rules (env: GRYPE_VEX_ADD)
vex-add: []

# match kernel-header packages with upstream kernel as kernel vulnerabilities (env: GRYPE_MATCH_UPSTREAM_KERNEL_HEADERS)
match-upstream-kernel-headers: false

db:
  # location to write the vulnerability database cache (env: GRYPE_DB_CACHE_DIR)
  cache-dir: '~/Library/Caches/grype/db'

  # URL of the vulnerability database (env: GRYPE_DB_UPDATE_URL)
  update-url: 'https://grype.anchore.io/databases'

  # certificate to trust download the database and listing file (env: GRYPE_DB_CA_CERT)
  ca-cert: ''

  # check for database updates on execution (env: GRYPE_DB_AUTO_UPDATE)
  auto-update: true

  # validate the database matches the known hash each execution (env: GRYPE_DB_VALIDATE_BY_HASH_ON_START)
  validate-by-hash-on-start: true

  # ensure db build is no older than the max-allowed-built-age (env: GRYPE_DB_VALIDATE_AGE)
  validate-age: true

  # Max allowed age for vulnerability database,
  # age being the time since it was built
  # Default max age is 120h (or five days) (env: GRYPE_DB_MAX_ALLOWED_BUILT_AGE)
  max-allowed-built-age: 120h0m0s

  # fail the scan if unable to check for database updates (env: GRYPE_DB_REQUIRE_UPDATE_CHECK)
  require-update-check: false

  # Timeout for downloading GRYPE_DB_UPDATE_URL to see if the database needs to be downloaded
  # This file is ~156KiB as of 2024-04-17 so the download should be quick; adjust as needed (env: GRYPE_DB_UPDATE_AVAILABLE_TIMEOUT)
  update-available-timeout: 30s

  # Timeout for downloading actual vulnerability DB
  # The DB is ~156MB as of 2024-04-17 so slower connections may exceed the default timeout; adjust as needed (env: GRYPE_DB_UPDATE_DOWNLOAD_TIMEOUT)
  update-download-timeout: 5m0s

  # Maximum frequency to check for vulnerability database updates (env: GRYPE_DB_MAX_UPDATE_CHECK_FREQUENCY)
  max-update-check-frequency: 2h0m0s

log:
  # suppress all logging output (env: GRYPE_LOG_QUIET)
  quiet: false

  # explicitly set the logging level (available: [error warn info debug trace]) (env: GRYPE_LOG_LEVEL)
  level: 'warn'

  # file path to write logs to (env: GRYPE_LOG_FILE)
  file: ''

dev:
  # capture resource profiling data (available: [cpu, mem]) (env: GRYPE_DEV_PROFILE)
  profile: ''

  db:
    # show sql queries in trace logging (requires -vv) (env: GRYPE_DEV_DB_DEBUG)
    debug: false
```

## Future plans

The following areas of potential development are currently being investigated:

- Support for allowlist, package mapping


## Grype Logo

<p xmlns:cc="http://creativecommons.org/ns#" xmlns:dct="http://purl.org/dc/terms/"><a property="dct:title" rel="cc:attributionURL" href="https://anchore.com/wp-content/uploads/2024/11/grype-logo.svg">Grype Logo</a> by <a rel="cc:attributionURL dct:creator" property="cc:attributionName" href="https://anchore.com/">Anchore</a> is licensed under <a href="https://creativecommons.org/licenses/by/4.0/" target="_blank" rel="license noopener noreferrer" style="display:inline-block;">CC BY 4.0<img style="height:22px!important;margin-left:3px;vertical-align:text-bottom;" src="https://mirrors.creativecommons.org/presskit/icons/cc.svg" alt=""><img style="height:22px!important;margin-left:3px;vertical-align:text-bottom;" src="https://mirrors.creativecommons.org/presskit/icons/by.svg" alt=""></a></p>
