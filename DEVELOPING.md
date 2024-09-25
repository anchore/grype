# Developing

There are a few useful things to know before diving into the codebase. This project depends on a few things being available like a vulnerability database, which you might want to create manually instead of retrieving a released version.

## Getting started

After cloning do the following:

1. run `go build ./cmd/grype` to get a binary named `main` from the source (use `-o <name>` to get a differently named binary), or optionally `go run ./cmd/grype` to run from source.

In order to run tests and build all artifacts:

1. run `make bootstrap` to download go mod dependencies, create the `/.tmp` dir, and download helper utilities (this only needs to be done once or when build tools are updated).
2. run `make` to run linting, tests, and other verifications to make certain everything is working alright.

The main make tasks for common static analysis and testing are `lint`, `format`, `lint-fix`, `unit`, and `integration`.

See `make help` for all the current make tasks.

## Relationship to Syft

Grype uses Syft as a library for all-things related to obtaining and parsing the given scan target (pulling container
images, parsing container images, indexing directories, cataloging packages, etc). Releases of Grype should
always use released versions of Syft (commits that are tagged and show up in the GitHub releases page). However,
continually integrating unreleased Syft changes into Grype incrementally is encouraged
(e.g. `go get github.com/anchore/syft@main`) as long as by the time a release is cut the Syft version is updated
to a released version (e.g. `go get github.com/anchore/syft@v<semantic-version>`).

## Inspecting the database

The currently supported database format is Sqlite3. Install `sqlite3` in your system and ensure that the `sqlite3` executable is available in your path. Ask `grype` about the location of the database, which will be different depending on the operating system:

```
$ go run ./cmd/grype db status
Location:  /Users/alfredo/Library/Caches/grype/db
Built:  2020-07-31 08:18:29 +0000 UTC
Current DB Version:  1
Require DB Version:  1
Status: Valid
```

The database is located within the XDG_CACHE_HOME path. To verify the database filename, list that path:

```
# OSX-specific path
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

## Adding a Data Source

These are the steps for adding a new data source to Grype. For example,
maybe we don't have vulnerabilities for your favorite Linux yet, or
maybe a language you work in hosts a vulnerability feed on their package
manager, and you would like to add it to Grype. Here is an outline of the
process.

### Step 1: Ensure Syft can Find what you want to Match

Grype uses [Syft](https://github.com/anchore/syft) to scan artifacts.

Before Grype can tell you whether a package is vulnerable, Syft needs
to be able to correctly identify the package.

If you're adding a new distro, you could run something like:

``` sh
syft -o json my-favorite-distro:latest | jq .distro
```

and make sure you agree with what you see. Syft will automatically
try to parse distro information from `/etc/os-release`, so you probably
don't need to make a change here, but it's a good idea to check.

Next, make sure syft can find packages you want:

``` sh
syft my-favorite-distro:latest
```

and take a look at the resulting table. Are you seeing the OS packages you'd
expect to see? For example, here's `alpine:latest` as of this writing:

``` sh
$ syft -o json alpine:latest | jq .distro
{
  "prettyName": "Alpine Linux v3.20",
  "name": "Alpine Linux",
  "id": "alpine",
  "versionID": "3.20.0",
  "homeURL": "https://alpinelinux.org/",
  "bugReportURL": "https://gitlab.alpinelinux.org/alpine/aports/-/issues"
}
$ syft alpine:latest
 ✔ Loaded image                                                  alpine:latest
 ... snip ...
NAME                    VERSION      TYPE   
alpine-baselayout       3.6.5-r0     apk     
alpine-baselayout-data  3.6.5-r0     apk     
alpine-keys             2.4-r1       apk     
...
```

Syft is identifying Alpine Linux correctly, and is finding `apk` packages (that
is, packages from Alpine's package manager), so we're good to go.

If Syft does not identify your the new distro or the its package manager's
packages correctly, please [open an issue
there](https://github.com/anchore/syft/issues/new?assignees=&labels=enhancement&projects=&template=feature_request.md&title=)


### Step 2. Add a Vunnel Provider

[Vunnel](https://github.com/anchore/vunnel) is a project that serves as an
adapter layer between vulnerability providers and Grype's code base. The main
coding work of adding a data source to Grype is to write a Vunnel provider
that takes the vulnerability data from its source and renders it in a format
that [Grype DB](https://github.com/anchore/grype-db) speaks, so that it can
be written into the database that grype downloads on each execution.

Create a new directory in which to clone 3 repos:

1. This repo, grype
2. [Vunnel](https://github.com/anchore/vunnel)
3. [Grype DB](https://github.com/anchore/grype-db)

So that it looks like this:

``` sh
.
├── grype
├── grype-db
└── vunnel
```

The majority of the work will be done within Vunnel. Vunnel
has a command `make dev` that has a few effects:

1. It compiles `grype` and `grype-db` binaries from the source code in the
   sibling directories
2. It writes config files for `grype` and `grype-db` so that they use the
   development vunnel
3. Creates a `poetry shell` to put vunnel and its python dev tools on PATH

For more details on actually building the vunnel provider, see the
[Vunnel development docs](https://github.com/anchore/vunnel/blob/main/DEVELOPING.md)
